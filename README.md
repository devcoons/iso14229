# ISO14229-1 Unified Diagnostic Protocol
![C/C++ CI](https://github.com/devcoons/iso14229/workflows/C/C++%20CI/badge.svg)

*Compiler flags: **-O3 -Wfatal-errors -Wall -std=c11***

An implementation of the **ISO14229-1 (UDS)** server. The library sits on top of ISO-TP (ISO 15765-2): your code feeds received CAN frames into ISO-TP and sends the frames ISO-TP asks to transmit. UDS services are filled in by tables in your application. The files in `binding/` are templates for those tables.

Call `iso14229_init()` once, then call `iso14229_process()` from the main loop.

```c
void app_init(void)
{
	iso14229_init();
}

void app_loop(void)
{
	iso14229_process();
}
```

On every received diagnostic CAN frame, pass it to ISO-TP:

```c
iso15765_enqueue(&uds_server.nl, &frame);
```

## What the build needs

`lib_iso14229.h` compiles the server only when all of these headers are on the include path:

- an STM32 HAL header: `stm32l4xx_hal.h`, `stm32l5xx_hal.h`, or `stm32h7xx_hal.h`
- `lib_iso15765.h` (ISO-TP)
- `lib_iso14229_config.h` (copy `lib_iso14229_config.h.template`)
- `lib_crypto.h`, which must provide `crc16_ccitt()` (used by TransferData)

Copy `lib_iso14229_shim.c.template` and implement the four functions the server calls:

| Function | Role |
|---|---|
| `iso14229_getms()` | millisecond tick, usually `HAL_GetTick()` |
| `send_frame()` | transmit one CAN frame |
| `iso14229_postinit()` | register the CAN receive filters and call `iso15765_enqueue` |
| `iso14229_ecu_flash_write()` | program the bytes TransferData passes in |

SecurityAccess also calls `random32()` for the seed and `xTaskGetTickCount()` for the delay after a wrong key. ECUReset calls `osDelay()` while it waits for the positive response to finish transmitting.

`ISO14229_1_DEVICE_ADDRESS` in the config header is the server's ISO-TP address.

Every table below is an array whose length is the matching `ISO14229_1_NUMOF_*` macro. Declare it with that length. A zero `id` (or a `NULL` routine callback) is an unused slot. `uds_sessions`, `uds_security_accesses`, `uds_routines`, `uds_read_data_by_id`, `uds_write_data_by_id`, `uds_ecu_reset`, `uds_download_request`, and `uds_tranfer_data` must all be defined or the link fails. `uds_dtc` has an empty default; define your own array to replace it.

## Sessions and security

Most services check two fields on the item you register:

- `session` must equal the **id of the session that is active right now**. A data identifier registered for `UDS_DIAG_EXTDS` answers only while the extended session is the active one.
- `security_level` of `0xFF` means the item is open. Any other value requires SecurityAccess to be unlocked at that level or a higher one. InputOutputControl is the exception: the unlocked level must match exactly.

`DiagnosticSessionControl`, `SecurityAccess`, `RequestDownload`, `TransferData`, and `RequestTransferExit` run only when the request is physically addressed.

A service that is switched off in the server answers NRC `0x11` (`serviceNotSupported`). Those services are listed at the end.

## DiagnosticSessionControl — `0x10`

Active as soon as `uds_sessions` contains the session. `A_ACTIVE` is the session in use at startup. `A_INACTIVE` can be entered. `A_LOCKED` is rejected with NRC `0x22` until your code changes `sts` to `A_INACTIVE`.

`timeout.max_response` is sent as P2, `timeout.time_limit` is sent as P2* and is also the inactivity timeout in milliseconds. `on_opening` runs when the session becomes active.

```c
static void enter_extended(void)
{
	/* application work when 10 03 succeeds */
}

uds_session_t uds_sessions[ISO14229_1_NUMOF_DIAGSESSIONS] =
{
	{.id = UDS_DIAG_DS,    .default_sts = A_ACTIVE,   .sts = A_ACTIVE,
	 .timeout.time_limit = 5000, .timeout.max_response = 50},
	{.id = UDS_DIAG_EXTDS, .default_sts = A_INACTIVE, .sts = A_INACTIVE,
	 .timeout.time_limit = 5000, .timeout.max_response = 50,
	 .on_opening = enter_extended},
	{.id = UDS_DIAG_PRGS,  .default_sts = A_LOCKED,   .sts = A_LOCKED,
	 .timeout.time_limit = 5000, .timeout.max_response = 50},
};
```

Tester: `10 03` enters the extended session. The response is `50 03` followed by P2 and P2*. Changing session locks security access again.

## ECUReset — `0x11`

Active when the matching callback in `uds_ecu_reset` is not `NULL`. The server sends the positive response, waits until ISO-TP confirms it, then calls the callback.

| Request | Callback |
|---|---|
| `11 01` hardReset | `cb_HR` |
| `11 02` keyOffOnReset | `cb_KOFFONR` |
| `11 03` softReset | `cb_SR` |
| `11 04` enableRapidPowerShutDown | `cb_ERPSD` |
| `11 05` disableRapidPowerShutDown | `cb_DRPSD` |

```c
static void hard_reset(void)
{
	NVIC_SystemReset();
}

uds_ecu_reset_t uds_ecu_reset =
{
	.cb_HR = hard_reset,
};
```

Tester: `11 01`. Response: `51 01`, then the ECU resets.

## SecurityAccess — `0x27`

Add one `uds_security_accesses` entry per level. `access_lvl` is the odd sub-function (`0x01`, `0x03`, …). `key_validation` receives the seed and returns the 32-bit key the tester must send back, big-endian. Provide `random32()`.

```c
static uint32_t key_from_seed(uint32_t seed)
{
	return seed ^ 0xA5A5A5A5u;
}

uds_security_access_t uds_security_accesses[ISO14229_1_NUMOF_SECURITYACCESSES] =
{
	{.access_lvl = 0x01, .default_sts = SA_INACTIVE, .sts = SA_INACTIVE,
	 .key_validation = key_from_seed},
};
```

Tester: `27 01` requests the seed (`67 01` plus 4 bytes). `27 02` plus those 4 key bytes unlocks the level (`67 02`). A wrong key starts a delay; further tries during the delay get NRC `0x37`.

Other services then accept this level by setting `security_level` to `0x01`.

## TesterPresent — `0x3E`

Always active. No table.

Tester: `3E 00` answers `7E 00`. `3E 80` is the same request with the response suppressed. Either one refreshes the active session timer.

## ReadDataByIdentifier — `0x22`

Put the identifier in `uds_read_data_by_id`. Two kinds of entry:

- `RDBID_AS_MEMORY_ADDRESS` copies `size` bytes from `address`. `as_msb = 1` sends them in reverse order.
- `RDBID_AS_RETVAL_OF_FUNC` calls `func(buffer, &size, func_arg)`. Write 1 to 128 bytes and set `*size`.

`fnr_enabled = 1` allows the same request on a functional address.

```c
static uint8_t serial_number[4] = {0x11, 0x22, 0x33, 0x44};

static void read_supply(uint8_t *buffer, uint8_t *size, uint32_t arg)
{
	(void)arg;
	buffer[0] = 12;
	*size = 1;
}

uds_read_data_by_id_t uds_read_data_by_id[ISO14229_1_NUMOF_READDATABYID] =
{
	{.id = 0xF190, .session = UDS_DIAG_DS, .security_level = 0xFF, .fnr_enabled = 1,
	 .type = RDBID_AS_MEMORY_ADDRESS,
	 .data.as_addr.address = serial_number, .data.as_addr.size = 4, .data.as_addr.as_msb = 0},
	{.id = 0x010C, .session = UDS_DIAG_DS, .security_level = 0xFF, .fnr_enabled = 1,
	 .type = RDBID_AS_RETVAL_OF_FUNC,
	 .data.as_func.func = read_supply, .data.as_func.func_arg = 0},
};
```

Tester: `22 F1 90` returns `62 F1 90 11 22 33 44`. Several identifiers can be requested in one message (`22 F1 90 01 0C`).

## WriteDataByIdentifier — `0x2E`

Same session and security rules. The callback form checks `size` when it is not 0, then calls `func(data, length, func_arg)`. Return 0 to accept the write.

```c
static int write_serial(uint8_t *data, uint8_t length, uint32_t arg)
{
	(void)arg;
	if(length != 4)
		return 1;
	memcpy(serial_number, data, 4);
	return 0;
}

uds_write_data_by_id_t uds_write_data_by_id[ISO14229_1_NUMOF_WRITEDATABYID] =
{
	{.id = 0xF190, .session = UDS_DIAG_EXTDS, .security_level = 0x01, .fnr_enabled = 0,
	 .type = WRBID_AS_RETVAL_OF_FUNC,
	 .data.as_func.func = write_serial, .data.as_func.func_arg = 0, .data.as_func.size = 4},
};
```

A memory entry writes straight into a variable. `VAR_TYPE_U16` and `VAR_TYPE_U32` are stored big-endian. `VAR_TYPE_U8` and `VAR_TYPE_ARR` are copied as a byte string.

Tester, after extended session and security level 1: `2E F1 90 11 22 33 44`. Response: `6E F1 90`.

## ReadMemoryByAddress — `0x23`

Always active. No table. The byte after the service id is `sizeLength << 4 | addressLength`. The server reads that many bytes from the given address and returns them. The size must be 255 or less.

Tester: `23 14 20 00 01 00 04` reads 4 bytes at `0x20000100`. Response: `63` plus those bytes.

## ClearDiagnosticInformation — `0x14`

Always active. No extra table. `14 FF FF FF` clears every DTC and answers `54`. `14` plus the 3-byte code clears that one DTC. A code that is not in the table gets NRC `0x31`.

After a clear, each affected status byte is `UDS_DTC_STATUS_AFTER_CLEAR` (`0x50`). Override `iso14229_dtc_on_clear()` to store that to non-volatile memory.

## ReadDTCInformation — `0x19`

Define `uds_dtc` with the DTCs the ECU supports. A code of zero is an empty slot. Set `ISO14229_1_NUMOF_DTC` to the array length. If you do not define the array, the server still answers, with an empty list.

```c
uds_dtc_t uds_dtc[ISO14229_1_NUMOF_DTC] =
{
	{.high = 0x01, .middle = 0x23, .low = 0x45, .status = UDS_DTC_STATUS_AFTER_CLEAR},
	{.high = 0x06, .middle = 0x00, .low = 0x11, .status = UDS_DTC_STATUS_AFTER_CLEAR},
};

void on_fault(uint8_t failed)
{
	iso14229_dtc_set_result(UDS_DTC_CODE(0x01, 0x23, 0x45), failed);
}

void on_new_operation_cycle(void)
{
	iso14229_dtc_operation_cycle();
}
```

`iso14229_dtc_set_result()` records one finished test. A failure sets `testFailed`, pending, and confirmed. Confirmed stays set until a clear. Call `iso14229_dtc_operation_cycle()` once per operation cycle so pending can clear.

| Tester request | Response |
|---|---|
| `19 01 FF` | `59 01`, availability mask, format `0x01`, then the 16-bit count of DTCs whose status matches the mask |
| `19 02 08` | `59 02`, availability mask, then each confirmed DTC as 3 bytes plus status |
| `19 0A` | `59 0A`, availability mask, then every supported DTC |

Any other sub-function gets NRC `0x12`.

## InputOutputControlByIdentifier — `0x2F`

Set `ISO14229_1_NUMOF_IOCONTROL` to the number of controls. The table is an array of pointers, and every slot must point at a real `uds_io_control_by_id_t`. `security_level` must match the unlocked level exactly, or be `0xFF`.

`ptr_inactive` is the normal variable. While a short-term adjustment is active, `iso14229_srvc_ioc_get()` returns `out_val` instead. Leaving the control's session drops the override.

```c
static uint8_t lamp;
static uds_io_control_by_id_t lamp_ioc =
{
	.id = 0x0155,
	.session = UDS_DIAG_EXTDS,
	.security_level = 0xFF,
	.type = IOC_OUTPUT,
	.sts = IOC_INACTIVE,
	.var_type = VAR_TYPE_U8,
	.ptr_inactive = (intptr_t)&lamp,
	.ptr_iocontrol = (intptr_t)&lamp,
};

uds_io_control_by_id_t *uds_io_control_by_id[ISO14229_1_NUMOF_IOCONTROL] =
{
	&lamp_ioc,
};

void apply_outputs(void)
{
	lamp = *(uint8_t *)iso14229_srvc_ioc_get(&lamp_ioc);
}
```

Tester: `2F 01 55 03 01` (shortTermAdjustment, value 1). `2F 01 55 00` returns control to the ECU. `var_type` selects the width of the value (`U8`, `U16`, or `U32`).

## RoutineControl — `0x31`

Register a routine id and a callback. The callback is `uint8_t (*)(void *self, routine_command cmd, uint8_t *data, uint16_t size)`. Return `0` on success or an NRC such as `UDS_NRC_SFNS`. Commands are `RTN_START` (`0x01`), `RTN_STOP` (`0x02`), and `RTN_RESULT` (`0x03`).

To keep working after the response, set `((uds_routine_local_id_t *)self)->sts = RTN_ACTIVE`. `iso14229_process()` then calls the routine with `RTN_CONTINUE` until you set `sts` back to `RTN_INACTIVE`. Optional result bytes go in `rst` / `rst_sz` before returning 0.

```c
static uint8_t check_programming(void *self, routine_command cmd, uint8_t *data, uint16_t size)
{
	uds_routine_local_id_t *routine = self;
	(void)data;
	if(cmd != RTN_START || size != 0)
	{
		routine->sts = routine->default_sts;
		return UDS_NRC_SFNS;
	}
	return 0;
}

uds_routine_local_id_t uds_routines[ISO14229_1_NUMOF_ROUTINESBYLOCALID] =
{
	{.id = 0x0203, .session = UDS_DIAG_PRGS, .security_level = 0x01,
	 .default_sts = RTN_INACTIVE, .sts = RTN_INACTIVE,
	 .fnr_enabled = 0, .rountine = check_programming},
};
```

The callback field name is `rountine`. Tester: `31 01 02 03`. Response: `71 01 02 03 00`.

## RequestDownload — `0x34`

Define `uds_download_request` and `uds_tranfer_data`. `security_level` on the download request gates the service (`0xFF` leaves it open). The data format byte must be `0x00`. The address must be 3 or 4 bytes and the length 1 to 4 bytes.

```c
uds_request_download_t uds_download_request =
{
	.security_level = 0x01, .default_sts = RD_INACTIVE, .sts = RD_INACTIVE,
};

uds_tranfer_data_t uds_tranfer_data =
{
	.security_level = 0x01, .default_sts = TD_LOCKED, .sts = TD_LOCKED,
};
```

Tester: `34 00 44` plus a 4-byte address and a 4-byte size. Response: `74 20 02 00` (max block payload `0x0200` bytes). This arms TransferData. Bytes are programmed by `iso14229_ecu_flash_write()` in 64-byte chunks, so the address should be 32-byte aligned.

## TransferData — `0x36`

No separate table. It runs only after a successful RequestDownload. The first block sequence counter is `0x01`, then it increments. Each payload is at most `0x0200` bytes.

Tester: `36 01` plus the data bytes. Response: `76 01`.

## RequestTransferExit — `0x37`

No separate table. The request is 7 bytes: the service id, the CRC-16/CCITT of the transferred bytes (the same `crc16_ccitt` the server updates, high byte first), and the total length on 4 bytes. Both must match, and every byte from the download must already have been programmed.

Tester: `37 <crc hi> <crc lo> <length 4 bytes>`. A match answers `77` plus the CRC high byte and returns the transfer to its default state.

## Services that answer `serviceNotSupported`

These SIDs are present and switched off. A request gets NRC `0x11`. There is no table that turns them on:

`0x28` CommunicationControl, `0x29` Authentication, `0x84` SecuredDataTransmission, `0x85` ControlDTCSetting, `0x86` ResponseOnEvent, `0x87` LinkControl, `0x24` ReadScalingDataByIdentifier, `0x2A` ReadDataByPeriodicIdentifier, `0x2C` DynamicallyDefineDataIdentifier, `0x3D` WriteMemoryByAddress, `0x35` RequestUpload, `0x38` RequestFileTransfer.

## Development

This library is experimental and is still under development. The purpose is to create a complete ISO14229 library with all the described features. Feel free to suggest anything. If you use this library please ref.

## Contributing
We would love you to contribute to `iso14229-1`, pull requests are welcome!

## Support

Support me maintain this project https://paypal.me/iikem

## License
This project is released under the MIT License
