// The native composition module. sdk/cgo holds the messaging half of the native library: its
// handwritten C ABI (exports_message.go, callbacks_message.{c,h}, include/urnetwork_message.h),
// its tests and its C harness. It builds only laid over the core SDK's cgo package main, whose
// handles and C-string helpers it calls; the composition build does that. Its own go.mod keeps
// it out of the github.com/urnetwork/message/sdk module.
module github.com/urnetwork/message/sdk/cgo

go 1.26.5
