module github.com/urnetwork/message/protocol/testdata/wiregolden

go 1.26.3

require (
	github.com/urnetwork/connect v0.0.0
	github.com/urnetwork/message v0.0.0
	google.golang.org/protobuf v1.36.11
)

// the schema as connect committed it, from before it left connect: the pinned sibling
// connect-golden (.github/siblings.txt)
replace github.com/urnetwork/connect => ../../../../connect-golden

// this repository
replace github.com/urnetwork/message => ../../..
