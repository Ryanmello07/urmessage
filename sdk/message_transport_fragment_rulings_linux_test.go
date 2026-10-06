//go:build !sdk_mobile_bind

package sdk

// THE LINUX HALF OF messageFragmentPartSizeCopyRulings, for a copy of the part size only a linux build
// can see.
//
// unix.O_NONBLOCK is 0x800 on linux, which is 2048, the part size, and 4 on darwin and the BSDs. The
// gate's class is the VALUE, read off the type checker, so the flag is in it here and nowhere else. A
// Windows build cannot see it at all: the file is unix-only, and the syntax-tree pass over the files
// a build does not compile cannot evaluate an imported constant. An excuse in the portable table
// would be stale on every build but this one, so it lives here, and its twin holds the empty half.
//
// EMPTY here. Its one entry in urnetwork/sdk was the core SDK's bounded peer key-pin store, which
// opens its file with unix.O_NONBLOCK; that store stayed in the core SDK. The half is kept, empty,
// because what it is for is still true of this package: a copy only a linux build can see has
// nowhere else to be excused, and the gate fails on linux the day one appears.
var messageFragmentPartSizePlatformCopyRulings = map[string]string{}
