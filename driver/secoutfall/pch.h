#pragma once

// ntifs.h (not ntddk.h) owns the base declarations when fltkernel.h is in
// the picture — the reverse order collides on PEPROCESS/PETHREAD. ntifs is
// a superset: process/registry/IoCreateDeviceSecure all resolve from it.
#include <ntifs.h>
#include <fltKernel.h>
#include <wdmsec.h>
