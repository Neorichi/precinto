package fsx

import "syscall"

// oNoFollow: windows is not supported yet (D34). os.OpenFile passes the
// FILE_FLAG_* bits of its flag to CreateFile, and
// FILE_FLAG_OPEN_REPARSE_POINT opens a symlink or junction itself instead
// of its target: the closest equivalent of O_NOFOLLOW for a final
// component, so an incomplete port never follows a link silently.
const oNoFollow = syscall.FILE_FLAG_OPEN_REPARSE_POINT
