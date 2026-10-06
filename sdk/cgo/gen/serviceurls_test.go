package main

import (
	"errors"
	"testing"

	coresdk "github.com/urnetwork/sdk"

	messagesdk "github.com/urnetwork/message/sdk"
)

// MessageServiceUrls IS THE CORE SDK'S ServiceUrl FOR A NETWORK SPACE WITH NO OVERRIDES.
//
// message/sdk's MessageClientConfig takes explicit platform and api urls first, and keeps the
// host/env convenience (the native ABI's urnet_message_client_new takes a host and an env) through
// a small resolver of its own, MessageServiceUrls, so that the messaging SDK needs nothing from the
// core SDK. While this code lived in the core SDK it called ServiceUrl itself, with
// NetworkSpaceValues{}. This module is the one place both SDKs are linked, so this is where the two
// are held to the same answers: production and non-production envs, env spellings that differ only
// in case, and hosts that are a bare domain, a subdomain, an ip literal and a host with a port. The
// one deliberate difference is a blank host, which the resolver refuses and ServiceUrl would turn
// into "wss://connect.".
func TestMessageServiceUrlsAreTheCoreSdksServiceUrls(t *testing.T) {
	hosts := []string{"ur.io", "bringyour.com", "staging.ur.io", "203.0.113.53", "localhost:8443"}
	envs := []string{"", "main", "MAIN", "Main", "beta", "BETA", "dev", "test1"}
	rows := 0
	for _, host := range hosts {
		for _, env := range envs {
			key := &coresdk.NetworkSpaceKey{HostName: host, EnvName: coresdk.NormalEnvName(env)}
			values := &coresdk.NetworkSpaceValues{}
			wantPlatform := coresdk.ServiceUrl(key, values, "wss", "connect")
			wantApi := coresdk.ServiceUrl(key, values, "https", "api")
			platform, api, err := messagesdk.MessageServiceUrls(host, env)
			if err != nil {
				t.Errorf("MessageServiceUrls(%q, %q) refused: %v", host, env, err)
				continue
			}
			if platform != wantPlatform || api != wantApi {
				t.Errorf("MessageServiceUrls(%q, %q) = %q, %q; the core SDK's ServiceUrl answers %q, %q",
					host, env, platform, api, wantPlatform, wantApi)
			}
			rows += 1
		}
	}
	for _, blank := range []string{"", " ", "\t"} {
		if _, _, err := messagesdk.MessageServiceUrls(blank, "main"); !errors.Is(err, messagesdk.ErrMessageClientNoHost) {
			t.Errorf("a blank host %q was not refused with ErrMessageClientNoHost: %v", blank, err)
		}
	}
	// the control: the comparison can tell two answers apart (a non-main env is not the main one)
	key := &coresdk.NetworkSpaceKey{HostName: "ur.io", EnvName: coresdk.NormalEnvName("beta")}
	if main, _, _ := messagesdk.MessageServiceUrls("ur.io", "main"); main == coresdk.ServiceUrl(key, &coresdk.NetworkSpaceValues{}, "wss", "connect") {
		t.Fatal("CONTROL FAILED: the main and beta platform urls compare equal, so equality above proves nothing")
	}
	t.Logf("%d host/env rows agree, platform and api, and %d blank hosts are refused", rows, 3)
}
