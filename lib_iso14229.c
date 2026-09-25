/*!
@file   iso14229_1.c
@brief  Source file of the ISO14229-1 library
@t.odo	-
---------------------------------------------------------------------------
MIT License

Copyright (c) 2020 Ioannis D. (devcoons)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
/******************************************************************************
* Preprocessor Definitions & Macros
******************************************************************************/

/******************************************************************************
* Includes
******************************************************************************/

#include "lib_iso14229.h"
#include <string.h>

#ifdef LIB_ISO14229_1_ENABLED


/******************************************************************************
* Enumerations, structures & Variables
******************************************************************************/

static iso14299_1_sid_t sid_list[] =
{
	{.sid = UDS_SRVC_DiagnosticSessionControl, 		.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_ECUReset, 				.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_SecurityAccess, 			.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_CommunicationControl, 			.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_TesterPresent, 			.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_Authentication, 			.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_SecuredDataTransmission, 		.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_ControlDTCSetting, 			.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_ResponseOnEvent, 			.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_LinkControl, 				.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_ReadDataByIdentifier, 			.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_ReadMemoryByAddress, 			.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_ReadScalingDataByIdentifier, 		.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_ReadDataByPeriodicIdentifier, 		.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_DynamicallyDefineDataIdentifier, 	.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_WriteDataByIdentifier, 		.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_WriteMemoryByAddress, 			.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_ClearDiagnosticInformation, 		.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_ReadDTCInformation, 			.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_InputOutputControlByIdentifier, 	.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_RoutineControl, 			.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_RequestDownload, 			.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_RequestUpload, 			.is_supported = iso14229_1_NO },
	{.sid = UDS_SRVC_TransferData, 				.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_RequestTransferExit, 			.is_supported = iso14229_1_YES },
	{.sid = UDS_SRVC_RequestFileTransfer, 			.is_supported = iso14229_1_NO }
};

static n_req_t out_frame =
{
        .n_ai.n_pr = 0x06,
        .n_ai.n_sa = ISO14229_1_DEVICE_ADDRESS,
        .n_ai.n_ta = 0x00,
        .n_ai.n_ae = 0x00,
        .n_ai.n_tt = N_TA_T_PHY,
        .msg = {0},
        .msg_sz = 0,
};

__attribute__ ((section(".buffers"))) iso14229_t uds_server =
{
	.n_pr 			= 0x06,
	.n_sa 			= ISO14229_1_DEVICE_ADDRESS,
	.nl.addr_md 		= N_ADM_FIXED,
	.nl.fr_id_type 		= CBUS_ID_T_EXTENDED,
	.nl.clbs.get_ms 	= iso14229_getms,
	.nl.config.stmin 	= 0x03,
	.nl.config.bs 		= 0x0F,
	.nl.config.n_bs 	= 100,
	.nl.config.n_cr 	= 3,
	.last_updated		= 0
};

static __attribute__ ((section(".buffers")))
					n_indn_t iso14229_1_received_indn = {0};
static __attribute__ ((section(".buffers")))
					uint8_t transfer_data_collection[UDS_TDC_SZ] = {0};
static __attribute__ ((section(".buffers")))
					uint8_t temporary_flash_64bytes[256] = {0};
static __attribute__ ((section(".buffers")))
					uint8_t iso14229_1_temporary_buffer[514] = {0};

#if ISO14229_1_NUMOF_DTC > 0
/* Empty table. Define uds_dtc in the application to replace it. */
__attribute__ ((weak, aligned (4)))
uds_dtc_t uds_dtc[ISO14229_1_NUMOF_DTC];
#endif
static __attribute__ ((section(".buffers")))
					uint32_t transfer_data_collection_pos =  0;
static __attribute__ ((section(".buffers")))
					uint32_t iso14229_1_timeout_extra_time = 0;

/******************************************************************************
* Declaration | Static Functions
******************************************************************************/

static void indn(n_indn_t* info);
static void on_error(n_rslt err_type);
static uint32_t uds_load_be(const uint8_t *data, uint8_t length);

/******************************************************************************
* Definition  | Static Functions
******************************************************************************/

static void on_error(n_rslt err_type)
{
	uds_server.errn = 1;
	UNUSED(err_type);
}

static void indn(n_indn_t* info)
{
	if(info->rslt != N_OK)
		return;

	memmove(&iso14229_1_received_indn, info,sizeof(n_indn_t));
	uds_server.p_msg = 1;
}

static void cfm(n_cfm_t* info)
{
	uds_server.s_msg = 1;
	UNUSED(info);
}

static uint32_t uds_load_be(const uint8_t *data, uint8_t length)
{
	uint32_t value = 0;

	for(uint8_t i = 0; i < length; i++)
		value = (value << 8) | data[i];

	return value;
}

/******************************************************************************
* Definition  | Public Functions
******************************************************************************/

void iso14229_init()
{
	memset(&iso14229_1_received_indn,0,sizeof(n_indn_t));
	memset(transfer_data_collection,0,UDS_TDC_SZ);
	memset(temporary_flash_64bytes,0,256);
	memset(iso14229_1_temporary_buffer,0,514);

	transfer_data_collection_pos =  0;
	iso14229_1_timeout_extra_time = 0;

	uds_server.n_pr = 0x06;
	uds_server.n_sa = ISO14229_1_DEVICE_ADDRESS;
	uds_server.p_msg = 0;

	memset(&uds_server.nl,0,sizeof(iso15765_t));
	uds_server.nl.addr_md = N_ADM_FIXED;
	uds_server.nl.fr_id_type = CBUS_ID_T_EXTENDED;
	uds_server.nl.clbs.send_frame = send_frame;
	uds_server.nl.clbs.on_error = on_error;
	uds_server.nl.clbs.get_ms = iso14229_getms;
	uds_server.nl.clbs.indn = indn;
	uds_server.nl.clbs.cfm = cfm;

	uds_server.nl.config.stmin = 0x2;
	uds_server.nl.config.bs = 0x00;
	uds_server.nl.config.n_bs = 0x96;
	uds_server.nl.config.n_cr = 0x96;
	uds_server.last_updated = iso14229_getms();
	iso15765_init(&uds_server.nl);

	iso14229_postinit();
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

uint8_t iso14229_inactive()
{
	if(uds_sessions[0].sts == A_ACTIVE)
	{
		if((uds_server.last_updated + 128 + iso14229_1_timeout_extra_time) < iso14229_getms())
			return 0;
	}
	return 1;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

uint8_t iso14229_process()
{
	iso14229_1_srvc_timeouts();


	if((iso15765_process(&uds_server.nl) & N_IDLE) == 0)
	{
		uds_server.last_updated = iso14229_getms();
	}

	if(iso14229_1_srvc_routines_process() == RTN_ACTIVE)
	{
		uds_server.last_updated = iso14229_getms();
	}

	iso14229_1_srvc_input_output_control_process();

	if(uds_server.p_msg != 1)
		return 0;

	uds_server.last_updated = iso14229_getms();

	uds_server.p_msg = 0;

	if(iso14229_1_received_indn.msg_sz < 1)
		return 1;

	if(sid_supported(iso14229_1_received_indn.msg[0]) != iso14229_1_YES)
		goto gt_iso14229_process_nack;

	iso14229_1_srvc_diagnostic_session_refresh_timeout();

	uint8_t is_fnr = iso14229_1_received_indn.n_ai.n_tt == N_TA_T_FUNC ? 1 : 0;


	switch(iso14229_1_received_indn.msg[0])
	{
	case UDS_SRVC_DiagnosticSessionControl:
		if(is_fnr == 0)
			iso14229_1_srvc_diagnostic_session_control();
		break;
	case UDS_SRVC_ECUReset:
		iso14229_1_uds_srvc_ecu_reset();
		break;
	case UDS_SRVC_SecurityAccess:
		if(is_fnr == 0)
			iso14229_1_srvc_security_access();
		break;
	case UDS_SRVC_CommunicationControl:
		break;
	case UDS_SRVC_TesterPresent:
		iso14229_1_srvc_tester_present();
		break;
	case UDS_SRVC_Authentication:
		break;
	case UDS_SRVC_SecuredDataTransmission:
		break;
	case UDS_SRVC_ControlDTCSetting:
		break;
	case UDS_SRVC_ResponseOnEvent:
		break;
	case UDS_SRVC_LinkControl:
		break;
	case UDS_SRVC_ReadDataByIdentifier:
		iso14229_srvc_read_data_by_localid();
		iso14229_1_timeout_extra_time = 5000;
		break;
	case UDS_SRVC_ReadMemoryByAddress:
		iso14229_1_srvc_read_memory_by_address();
		break;
	case UDS_SRVC_ReadScalingDataByIdentifier:
		break;
	case UDS_SRVC_ReadDataByPeriodicIdentifier:
		break;
	case UDS_SRVC_DynamicallyDefineDataIdentifier:
		break;
	case UDS_SRVC_WriteDataByIdentifier:
		iso14229_srvc_write_data_by_localid();
		iso14229_1_timeout_extra_time = 5000;
		break;
	case UDS_SRVC_WriteMemoryByAddress:
		break;
	case UDS_SRVC_ClearDiagnosticInformation:
		iso14229_1_srvc_ClearDiagnosticInformation();
		break;
	case UDS_SRVC_ReadDTCInformation:
		iso14229_1_srvc_readDTCinformation();
		break;
	case UDS_SRVC_InputOutputControlByIdentifier:
		iso14229_1_srvc_input_output_control_by_identifier();
		break;
	case UDS_SRVC_RoutineControl:
		iso14229_1_srvc_routine_control();
		break;
	case UDS_SRVC_RequestDownload:
		if(is_fnr == 0)
			iso14229_1_uds_srvc_request_download();
		break;
	case UDS_SRVC_RequestUpload:
		break;
	case UDS_SRVC_TransferData:
		if(is_fnr == 0)
			iso14229_1_srvc_tranfer_data();
		break;
	case UDS_SRVC_RequestTransferExit:
		if(is_fnr == 0)
			iso14229_1_srvc_request_transfer_exit();
		break;
	case UDS_SRVC_RequestFileTransfer:
		break;
	default:
		break;
	}

	return 1;
	gt_iso14229_process_nack:
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				iso14229_1_received_indn.msg[0],UDS_NRC_SNS);
		return 1;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

iso14229_1_status sid_supported(uint8_t sid)
{
	uint32_t list_sz = sizeof(sid_list)/sizeof(iso14299_1_sid_t);

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(sid_list[i].sid == sid)
			return sid_list[i].is_supported == iso14229_1_YES
				   ? iso14229_1_YES
				   : iso14229_1_NO;
	}

	return iso14229_1_NO;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

iso14229_1_status sub_sid_supported(uint8_t sid,uint8_t sub)
{
	uint32_t list_sz = sizeof(sid_list)/sizeof(iso14299_1_sid_t);

	UNUSED(sub);

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(sid_list[i].sid == sid)
			return sid_list[i].is_supported == iso14229_1_YES
				   ? iso14229_1_YES
				   : iso14229_1_NO;
	}
	return iso14229_1_NO;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_send(n_ai_t *ai, uint8_t* data, uint16_t sz)
{
	out_frame.n_ai.n_ae = ai->n_ae;
	out_frame.n_ai.n_sa = ISO14229_1_DEVICE_ADDRESS;
	out_frame.n_ai.n_ta = ai->n_sa;
	out_frame.n_ai.n_pr = ai->n_pr;
	out_frame.n_ai.n_tt = N_TA_T_PHY;
	out_frame.fr_fmt = iso14229_1_received_indn.fr_fmt;
	out_frame.msg_sz = sz;
	memmove(out_frame.msg,data,sz);
	iso15765_send(&uds_server.nl,&out_frame);
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_send_NRC(n_ai_t *ai,uint8_t sid, uint8_t code)
{
	static uint8_t data[3];

	/* ISO 14229-1: these NRCs are not sent for a functional request. */
	if(ai != NULL && ai->n_tt == N_TA_T_FUNC)
	{
		if(code == UDS_NRC_SNS || code == UDS_NRC_SFNS || code == UDS_NRC_ROOR
				|| code == UDS_NRC_SFNSIAS || code == UDS_NRC_SNSIAS)
			return;
	}

	data[0] = 0x7F;
	data[1] = sid;
	data[2] = code;
	iso14229_send(ai, data, code == 0 ? 2 : 3);
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_timeouts()
{
	uint32_t list_sz = sizeof(uds_sessions)/sizeof(uds_session_t);

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if((uds_sessions[i].sts & 0x0F) != 0 )
		{
			if((iso14229_getms() - uds_sessions[i].timeout.last_update) >  uds_sessions[i].timeout.time_limit )
			{
				uint32_t sa_list_sz = sizeof(uds_security_accesses)/sizeof(uds_security_access_t);

				for(register uint32_t j = 0;j<sa_list_sz;j++)
					uds_security_accesses[j].sts = uds_security_accesses[j].default_sts;

				if(uds_sessions[i].on_closing != NULL)
					uds_sessions[i].on_closing();

				for(register uint32_t j = 0;j<list_sz;j++)
				{
					uds_sessions[j].sts = uds_sessions[j].default_sts;
				}
				iso14229_1_srvc_diagnostic_session_refresh_timeout();
			}
		}
	}
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_request_transfer_exit()
{
	if( (iso14229_1_received_indn.msg_sz != 7))
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	if(uds_tranfer_data.sts != TD_ACTIVE || uds_tranfer_data.remaining_data_len!=0 || transfer_data_collection_pos !=0)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RSE);
		return;
	}

	uint16_t dtr_crc = (uint16_t)uds_load_be(&iso14229_1_received_indn.msg[1], 2);
	uint32_t dtr_len = uds_load_be(&iso14229_1_received_indn.msg[3], 4);

	if(dtr_crc == uds_tranfer_data.calculated_crc && dtr_len == uds_tranfer_data.expected_data_len)
	{
		iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		iso14229_1_temporary_buffer[1] = iso14229_1_received_indn.msg[1];
		uds_tranfer_data.sts = uds_tranfer_data.default_sts;
		uds_download_request.sts = uds_download_request.default_sts;
		iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,2);
	}
	else
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_GPF);
		return;
	}
	return;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

intptr_t iso14229_srvc_ioc_get(uds_io_control_by_id_t* h)
{
	if(h == NULL)
		return 0;

	if(h->ptr_iocontrol != h->ptr_inactive && h->ptr_iocontrol != (intptr_t)&h->out_val)
	{
		return h->ptr_inactive;
	}
	return h->ptr_iocontrol;
}


void iso14229_1_srvc_input_output_control_process()
{
	uint32_t sessions_list_sz = sizeof(uds_sessions) / sizeof(uds_session_t);
	int session_valid = -1;
	for(register uint32_t i = 0; i < sessions_list_sz; i++)
	{
		if(uds_sessions[i].sts == A_ACTIVE)
			session_valid = (int)i;
	}

	if(session_valid < 0)
		return;

	uint32_t list_sz = sizeof(uds_io_control_by_id)/sizeof(uds_io_control_by_id_t*);

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_io_control_by_id[i] == NULL)
			continue;

		if(uds_io_control_by_id[i]->sts == IOC_ACTIVE && uds_io_control_by_id[i]->session != uds_sessions[session_valid].id)
		{
			uds_io_control_by_id[i]->ptr_iocontrol = uds_io_control_by_id[i]->ptr_inactive;
			///RESET CONTROL TO MATLAB

			uds_io_control_by_id[i]->sts = IOC_INACTIVE;

		}
	}
}
/* --- DTC table helpers (ref: ISO14229-1 ReadDTC / ClearDiagnostic) ------- */

static uint32_t uds_dtc_code(const uds_dtc_t *dtc)
{
	return ((uint32_t)dtc->high << 16) | ((uint32_t)dtc->middle << 8) | dtc->low;
}

static uint8_t uds_dtc_reported_status(const uds_dtc_t *dtc)
{
	return dtc->status & UDS_DTC_STATUS_AVAILABILITY_MASK;
}

static uint8_t uds_dtc_status_matches(const uds_dtc_t *dtc, uint8_t mask)
{
	return (uds_dtc_reported_status(dtc) & mask) != 0;
}

static void uds_dtc_clear_record(uds_dtc_t *dtc)
{
	dtc->status = UDS_DTC_STATUS_AFTER_CLEAR;
}

/*
 * First failed result confirms the DTC. Confirmed stays set until a clear.
 * Pending stays set through the rest of this operation cycle, including a
 * later pass, and is cleared on the next cycle only if that cycle did not fail.
 */
static void uds_dtc_apply_result(uds_dtc_t *dtc, uint8_t failed)
{
	if(failed)
	{
		dtc->status |= UDS_DTC_STS_TF | UDS_DTC_STS_TFTOC | UDS_DTC_STS_PDTC
				| UDS_DTC_STS_CDTC | UDS_DTC_STS_TFSLC;
		dtc->status &= (uint8_t)~(UDS_DTC_STS_TNCSLC | UDS_DTC_STS_TNCTOC);
	}
	else
	{
		dtc->status &= (uint8_t)~UDS_DTC_STS_TF;
		dtc->status &= (uint8_t)~(UDS_DTC_STS_TNCSLC | UDS_DTC_STS_TNCTOC);
		if((dtc->status & UDS_DTC_STS_TFTOC) == 0)
			dtc->status &= (uint8_t)~UDS_DTC_STS_PDTC;
	}
}

static uint16_t uds_dtc_count_matching(uint8_t mask)
{
	uint32_t count = 0;

#if ISO14229_1_NUMOF_DTC > 0
	for(uint32_t i = 0; i < ISO14229_1_NUMOF_DTC; i++)
	{
		if(uds_dtc_code(&uds_dtc[i]) == 0)
			continue;
		if(uds_dtc_status_matches(&uds_dtc[i], mask) && count < 0xFFFFu)
			count++;
	}
#else
	(void)mask;
#endif
	return (uint16_t)count;
}

static uint8_t uds_dtc_append_records(uint8_t *buf, uint16_t *pos, uint16_t max_sz, uint8_t mask, uint8_t use_mask)
{
#if ISO14229_1_NUMOF_DTC > 0
	for(uint32_t i = 0; i < ISO14229_1_NUMOF_DTC; i++)
	{
		if(uds_dtc_code(&uds_dtc[i]) == 0)
			continue;
		if(use_mask && uds_dtc_status_matches(&uds_dtc[i], mask) == 0)
			continue;
		if(*pos > max_sz || (uint16_t)(max_sz - *pos) < 4u)
			return 0;

		buf[(*pos)++] = uds_dtc[i].high;
		buf[(*pos)++] = uds_dtc[i].middle;
		buf[(*pos)++] = uds_dtc[i].low;
		buf[(*pos)++] = uds_dtc_reported_status(&uds_dtc[i]);
	}
#else
	(void)buf;
	(void)pos;
	(void)max_sz;
	(void)mask;
	(void)use_mask;
#endif
	return 1;
}

__attribute__ ((weak)) void iso14229_dtc_on_clear(uint32_t group_of_dtc)
{
	(void)group_of_dtc;
}

uint8_t iso14229_dtc_set_result(uint32_t dtc, uint8_t failed)
{
	uint8_t found = 0;

#if ISO14229_1_NUMOF_DTC > 0
	if(dtc == 0)
		return 0;

	for(uint32_t i = 0; i < ISO14229_1_NUMOF_DTC; i++)
	{
		if(uds_dtc_code(&uds_dtc[i]) != dtc)
			continue;
		uds_dtc_apply_result(&uds_dtc[i], failed);
		found = 1;
	}
#else
	(void)dtc;
	(void)failed;
#endif
	return found;
}

void iso14229_dtc_operation_cycle(void)
{
#if ISO14229_1_NUMOF_DTC > 0
	for(uint32_t i = 0; i < ISO14229_1_NUMOF_DTC; i++)
	{
		if(uds_dtc_code(&uds_dtc[i]) == 0)
			continue;
		if((uds_dtc[i].status & UDS_DTC_STS_TFTOC) == 0)
			uds_dtc[i].status &= (uint8_t)~UDS_DTC_STS_PDTC;
		uds_dtc[i].status &= (uint8_t)~UDS_DTC_STS_TFTOC;
		uds_dtc[i].status |= UDS_DTC_STS_TNCTOC;
	}
#endif
}

/* --- ClearDiagnosticInformation (ref: ISO14229-1 service 0x14) ----------- */
void iso14229_1_srvc_ClearDiagnosticInformation(void)
{
	/* Request is SID + 3-byte groupOfDTC. */
	if(iso14229_1_received_indn.msg_sz != 4)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint32_t group = ((uint32_t)iso14229_1_received_indn.msg[1] << 16)
			| ((uint32_t)iso14229_1_received_indn.msg[2] << 8)
			| (uint32_t)iso14229_1_received_indn.msg[3];

	if(group == 0)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	uint8_t cleared = 0;

#if ISO14229_1_NUMOF_DTC > 0
	for(uint32_t i = 0; i < ISO14229_1_NUMOF_DTC; i++)
	{
		uint32_t code = uds_dtc_code(&uds_dtc[i]);
		if(code == 0)
			continue;
		if(group == UDS_DTC_GROUP_ALL || code == group)
		{
			uds_dtc_clear_record(&uds_dtc[i]);
			cleared = 1;
		}
	}
#endif

	/* 0xFFFFFF is always a supported group. Any other value must match a DTC. */
	if(group != UDS_DTC_GROUP_ALL && cleared == 0)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	iso14229_dtc_on_clear(group);

	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	iso14229_send(&iso14229_1_received_indn.n_ai, iso14229_1_temporary_buffer, 1);
}

/* --- ReadDTCInformation (ref: ISO14229-1 service 0x19) -------------------- */
void iso14229_1_srvc_readDTCinformation(void)
{
	/* Minimum request is SID + sub-function. The status mask, when present, is msg[2]. */
	if(iso14229_1_received_indn.msg_sz < 2)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint8_t sub = iso14229_1_received_indn.msg[1] & 0x7Fu;
	uint8_t suppress = iso14229_1_received_indn.msg[1] & 0x80u;
	uint8_t expected_sz = 0;

	switch(sub)
	{
	case UDS_RDTC_RNODTCBSM:	/* reportNumberOfDTCByStatusMask	 */
	case UDS_RDTC_RDTCBSM:		/* reportDTCByStatusMask		 */
		expected_sz = 3;
		break;
	case UDS_RDTC_RSUPDTC:		/* reportSupportedDTC			 */
		expected_sz = 2;
		break;
	default:
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SFNS);
		return;
	}

	if(iso14229_1_received_indn.msg_sz != expected_sz)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	iso14229_1_temporary_buffer[1] = sub;
	iso14229_1_temporary_buffer[2] = UDS_DTC_STATUS_AVAILABILITY_MASK;

	uint16_t response_sz = 3;

	if(sub == UDS_RDTC_RNODTCBSM)
	{
		uint16_t count = uds_dtc_count_matching(iso14229_1_received_indn.msg[2]);
		iso14229_1_temporary_buffer[3] = UDS_DTC_FORMAT_IDENTIFIER;
		iso14229_1_temporary_buffer[4] = (uint8_t)(count >> 8);
		iso14229_1_temporary_buffer[5] = (uint8_t)count;
		response_sz = 6;
	}
	else
	{
		uint8_t use_mask = sub == UDS_RDTC_RDTCBSM ? 1u : 0u;
		uint8_t mask = use_mask ? iso14229_1_received_indn.msg[2] : 0u;

		if(uds_dtc_append_records(iso14229_1_temporary_buffer, &response_sz,
				(uint16_t)sizeof(iso14229_1_temporary_buffer), mask, use_mask) == 0)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RTL);
			return;
		}
	}

	if(suppress)
		return;

	iso14229_send(&iso14229_1_received_indn.n_ai, iso14229_1_temporary_buffer, response_sz);
}
/* --- InputOutput control functional unit (ref:iso14229-1(2020) Cap 13 p.297) ------------ */
void iso14229_1_srvc_input_output_control_by_identifier()
{

	//Minimum lenght check
	if(iso14229_1_received_indn.msg_sz < 4)  //pag 301
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uds_io_control_by_id_t* current_iocontrol = NULL;
	//DID supports service 0x2F in active session AND InputOutput is support

	uint32_t list_sz = sizeof(uds_io_control_by_id)/sizeof(uds_io_control_by_id_t*);

	uint16_t data_id = 	iso14229_1_received_indn.msg[1]<<8 | iso14229_1_received_indn.msg[2];
	uint8_t session_valid = 0;
	uint8_t security_check = 0;

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_io_control_by_id[i] != NULL && uds_io_control_by_id[i]->id == data_id && uds_io_control_by_id[i]->id != 0)
		{
			current_iocontrol = uds_io_control_by_id[i];
			break;
		}
	}

	if(current_iocontrol == NULL)  // check if IO is present
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_ROOR);
		return;
	}

	list_sz = sizeof(uds_sessions) / sizeof(uds_session_t);

	for(register uint32_t i = 0; i < list_sz; i++)
	{
		if(uds_sessions[i].id == current_iocontrol->session && uds_sessions[i].sts == A_ACTIVE)
			session_valid = 1;
	}

	if(session_valid == 0)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}
	//Total length check


	//controlState is supported (if applicable) AND control mask is supported (if applicable)


	//authentication check ok? [Not used]

	//Security check ok for requested DID?
	uint32_t sa_list_sz = sizeof(uds_security_accesses)/sizeof(uds_security_access_t);

	for(register uint32_t j = 0;j<sa_list_sz;j++)
	{
		if(uds_security_accesses[j].access_lvl == current_iocontrol->security_level && uds_security_accesses[j].sts == SA_ACTIVE)
			security_check = 1;
	}

	if(security_check == 0 && current_iocontrol->security_level != 0xFF)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SAD);
		return;
	}

	//se arrivo qui attivo lo status ioc_active

	uint8_t ioc_param = iso14229_1_received_indn.msg[3];
	uint8_t value_len = 0;

	if(ioc_param >= 0x04)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	if(ioc_param == 0x03)
	{
		if(current_iocontrol->var_type == VAR_TYPE_U8 || current_iocontrol->var_type == VAR_TYPE_I8)
			value_len = 1;
		else if(current_iocontrol->var_type == VAR_TYPE_U16 || current_iocontrol->var_type == VAR_TYPE_I16)
			value_len = 2;
		else if(current_iocontrol->var_type == VAR_TYPE_U32 || current_iocontrol->var_type == VAR_TYPE_I32)
			value_len = 4;
		else
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
			return;
		}
	}

	if(iso14229_1_received_indn.msg_sz != (uint16_t)(4u + value_len))
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	if(value_len != 0)
		current_iocontrol->out_val = uds_load_be(&iso14229_1_received_indn.msg[4], value_len);

	switch(ioc_param)
	{
		case 0x00: /* returnControlToECU */
			current_iocontrol->ptr_iocontrol = current_iocontrol->ptr_inactive;
			current_iocontrol->sts = IOC_INACTIVE;
			break;
		case 0x01: /* resetToDefault */
		case 0x02: /* freezeCurrentState */
			current_iocontrol->sts = IOC_ACTIVE;
			break;
		case 0x03: /* shortTermAdjustment */
			current_iocontrol->ptr_iocontrol = (intptr_t)&current_iocontrol->out_val;
			current_iocontrol->sts = IOC_ACTIVE;
			break;
		default:
			break;
	}

	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	iso14229_1_temporary_buffer[1] = iso14229_1_received_indn.msg[1];
	iso14229_1_temporary_buffer[2] = iso14229_1_received_indn.msg[2];
	iso14229_1_temporary_buffer[3] = ioc_param;
	for(uint8_t i = 0; i < value_len; i++)
		iso14229_1_temporary_buffer[4u + i] = iso14229_1_received_indn.msg[4u + i];

	iso14229_send(&iso14229_1_received_indn.n_ai, iso14229_1_temporary_buffer, (uint16_t)(4u + value_len));

}
/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_routine_control()
{
	if(iso14229_1_received_indn.msg_sz < 4)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	volatile uds_routine_local_id_t* current_routine = NULL;
	uint8_t routine_cmd = iso14229_1_received_indn.msg[1] & 0x7Fu;
	uint8_t suppress = iso14229_1_received_indn.msg[1] & 0x80u;
	uint16_t routine_id = iso14229_1_received_indn.msg[2]<< 8 | iso14229_1_received_indn.msg[3];
	uint8_t session_valid = 0;
	uint8_t security_check = 0;
	uint8_t* routine_args = NULL;
	uint16_t routing_args_sz = 0;

	uint32_t list_sz = sizeof(uds_routines)/sizeof(uds_routine_local_id_t);

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_routines[i].id == routine_id && uds_routines[i].rountine != NULL)
		{
			current_routine = &uds_routines[i];
		}
	}

	if(current_routine == NULL)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai, __uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_ROOR);
		return;
	}

	uint8_t is_fnr = iso14229_1_received_indn.n_ai.n_tt == N_TA_T_FUNC ? 1 : 0;

	if(current_routine->fnr_enabled != 1 && is_fnr == 1)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai, __uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_ROOR);
		return;
	}

	list_sz = sizeof(uds_sessions) / sizeof(uds_session_t);

	for(register uint32_t i = 0; i < list_sz; i++)
	{
		if(uds_sessions[i].id == current_routine->session && uds_sessions[i].sts == A_ACTIVE)
			session_valid = 1;
	}

	if(session_valid == 0)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	uint32_t sa_list_sz = sizeof(uds_security_accesses)/sizeof(uds_security_access_t);

	for(register uint32_t j = 0;j<sa_list_sz;j++)
	{
		if(uds_security_accesses[j].access_lvl >= current_routine->security_level && uds_security_accesses[j].sts == SA_ACTIVE)
			security_check = 1;
	}

	if(security_check == 0 && current_routine->security_level != 0xFF)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SAD);
		return;
	}

	routing_args_sz = iso14229_1_received_indn.msg_sz - 4;

	if(routing_args_sz != 0)
		routine_args = &iso14229_1_received_indn.msg[4];

	current_routine->rst = NULL;
	current_routine->rst_sz = 0;

	uint8_t rslt = current_routine->rountine((void*)current_routine,(routine_command)routine_cmd,routine_args,routing_args_sz);

	if(rslt == 0)
	{
		if(current_routine->rst_sz > sizeof(iso14229_1_temporary_buffer) - 5)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RTL);
			return;
		}

		iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		iso14229_1_temporary_buffer[1] = routine_cmd;
		iso14229_1_temporary_buffer[2] = iso14229_1_received_indn.msg[2];
		iso14229_1_temporary_buffer[3] = iso14229_1_received_indn.msg[3];
		iso14229_1_temporary_buffer[4] = rslt;
		if(current_routine->rst != NULL && current_routine->rst_sz !=0)
			memmove(&iso14229_1_temporary_buffer[5],current_routine->rst,current_routine->rst_sz);

		if(suppress == 0)
			iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,(uint16_t)(5u + current_routine->rst_sz));
	}
	else
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),rslt);
	}

	return;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

routine_status iso14229_1_srvc_routines_process()
{
	uint32_t list_sz = sizeof(uds_routines)/sizeof(uds_routine_local_id_t);
	routine_status sts =  RTN_INACTIVE;

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_routines[i].sts == RTN_ACTIVE && uds_routines[i].rountine != NULL)
		{
			sts = RTN_ACTIVE;
			uds_routines[i].rountine(&uds_routines[i],RTN_CONTINUE,NULL,0);
		}
	}

	if(sts == RTN_ACTIVE)
		iso14229_1_srvc_diagnostic_session_refresh_timeout();

	return sts;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

static uint32_t inc_delay = 0;
static uint32_t last_trial_time = 0;

void iso14229_1_srvc_security_access()
{
	uint32_t key;
	uint32_t resp_key;
	uds_security_access_t *current_sa = NULL;

	if(iso14229_1_received_indn.msg_sz < 2)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint8_t sub = iso14229_1_received_indn.msg[1] & 0x7Fu;
	uint8_t suppress = iso14229_1_received_indn.msg[1] & 0x80u;
	uint8_t req_type = sub & 0x01u;
	uint8_t req_sa_lvl = req_type == 1 ? sub : (uint8_t)(sub - 1u);

	uint32_t list_sz = sizeof(uds_security_accesses)/sizeof(uds_security_access_t);

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_security_accesses[i].access_lvl == req_sa_lvl)
		{
			current_sa = &uds_security_accesses[i];
		}
	}

	if(current_sa == NULL)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SFNS);
		return;
	}

	if(current_sa->sts == SA_NOT_EXISTS)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SFNS);
		return;
	}

	if(req_type == 0x00 && current_sa->sts != SA_IN_PROGRESS)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RSE);
		return;
	}

	if(iso14229_1_received_indn.msg_sz != 2  && req_type == 0x01)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	if(iso14229_1_received_indn.msg_sz != 6  && req_type == 0x00)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	if(last_trial_time !=0 && inc_delay != 0)
	{
		uint32_t delay_ms = inc_delay > 5 ? (60u * 60u * 1000u) : (inc_delay * 2000u);
		if((xTaskGetTickCount() - last_trial_time) < delay_ms)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RTDNE);
			return;
		}
	}

	if(current_sa->sts == SA_ACTIVE && req_type == 0x01)
	{
		iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		iso14229_1_temporary_buffer[1] = sub;
		iso14229_1_temporary_buffer[2] = 0;
		iso14229_1_temporary_buffer[3] = 0;
		iso14229_1_temporary_buffer[4] = 0;
		iso14229_1_temporary_buffer[5] = 0;
		if(suppress == 0)
			iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,6);
		return;
	}

	switch(req_type)
	{
	case 0x01:
		for(register uint32_t i = 0;i<list_sz;i++)
		{
			if(uds_security_accesses[i].sts == SA_IN_PROGRESS)
				uds_security_accesses[i].sts = uds_security_accesses[i].default_sts;
		}
		current_sa->sts = SA_IN_PROGRESS;
		current_sa->current_seed = random32();
		iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		iso14229_1_temporary_buffer[1] = sub;
		iso14229_1_temporary_buffer[2] = (current_sa->current_seed & 0xFF000000) >> 24;
		iso14229_1_temporary_buffer[3] = (current_sa->current_seed & 0x00FF0000) >> 16;
		iso14229_1_temporary_buffer[4] = (current_sa->current_seed & 0x0000FF00) >> 8;
		iso14229_1_temporary_buffer[5] = (current_sa->current_seed & 0x000000FF) >> 0;
		if(suppress == 0)
			iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,6);
		break;

	case 0x00:
		key = current_sa->key_validation != NULL ? current_sa->key_validation(current_sa->current_seed) : current_sa->current_seed;
		resp_key = uds_load_be(&iso14229_1_received_indn.msg[2], 4);

		if(key == resp_key)
		{
			for(register uint32_t i = 0;i<list_sz;i++)
			{
				uds_security_accesses[i].sts = uds_security_accesses[i].default_sts;
			}
			last_trial_time = 0;
			inc_delay=0;
			current_sa->sts = SA_ACTIVE;
			iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
			iso14229_1_temporary_buffer[1] = sub;
			if(suppress == 0)
				iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,2);
			return;
		}
		else
		{
			last_trial_time = xTaskGetTickCount();
			inc_delay+=1;
			current_sa->sts = current_sa->default_sts;
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IK);
			return;
		}
		break;
	default:
		break;
	}
	return;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_tester_present()
{
	if(iso14229_1_received_indn.msg_sz != 2)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	if((__uds_get_subfunction(iso14229_1_received_indn.msg) & 0x7Fu) != 0)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SFNS);
		return;
	}

	if((__uds_get_subfunction(iso14229_1_received_indn.msg) & 0x80u) == 0)
	{
		iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		iso14229_1_temporary_buffer[1] = 0x00;
		iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,2);
	}

	iso14229_1_srvc_diagnostic_session_refresh_timeout();
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_tranfer_data()
{
	if(iso14229_1_received_indn.msg_sz < 3 || (iso14229_1_received_indn.msg_sz - 2) > 0x200)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	if(uds_tranfer_data.sts != TD_INACTIVE && uds_tranfer_data.sts != TD_ACTIVE)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RSE);
		return;
	}

	/* After RequestDownload the first block is 0x01. Later blocks increment, wrapping FF -> 00. */
	uint8_t expected = uds_tranfer_data.sts == TD_INACTIVE ? 0x01u : (uint8_t)uds_tranfer_data.block_counter;
	if(iso14229_1_received_indn.msg[1] != expected)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_WBSC);
		return;
	}

	uint32_t payload = (uint32_t)iso14229_1_received_indn.msg_sz - 2u;
	uint8_t align = 0;
	if((uds_tranfer_data.current_address % 0x20u) != 0)
		align = (uint8_t)(uds_tranfer_data.current_address % 0x20u);

	if(transfer_data_collection_pos > uds_tranfer_data.remaining_data_len
			|| payload > uds_tranfer_data.remaining_data_len - transfer_data_collection_pos
			|| transfer_data_collection_pos + payload + align > UDS_TDC_SZ)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	uds_tranfer_data.block_counter = (uint8_t)(iso14229_1_received_indn.msg[1] + 1u);
	memmove(&transfer_data_collection[transfer_data_collection_pos], &iso14229_1_received_indn.msg[2], payload);
	transfer_data_collection_pos += payload;

	uds_tranfer_data.calculated_crc = crc16_ccitt(uds_tranfer_data.calculated_crc, &iso14229_1_received_indn.msg[2], iso14229_1_received_indn.msg_sz - 2);

	uint32_t t_transfer_data_collection_pos = 0;

	if(align != 0)
	{
		uint8_t diff = align;

		uds_tranfer_data.current_address -= diff;
		memmove(&transfer_data_collection[diff],transfer_data_collection,transfer_data_collection_pos);
		memmove(transfer_data_collection,(uint8_t*)(uintptr_t)uds_tranfer_data.current_address,diff);
		uds_tranfer_data.remaining_data_len+=diff;
		transfer_data_collection_pos += diff;
	}

	for(uint32_t i=0; i + 64u <= transfer_data_collection_pos && uds_tranfer_data.remaining_data_len >= 64u; i+=64)
	{
		iso14229_ecu_flash_write(uds_tranfer_data.current_address, &transfer_data_collection[i], 64);
		t_transfer_data_collection_pos+=64;
		uds_tranfer_data.current_address+=64;
		uds_tranfer_data.remaining_data_len -= 64;
	}

	memmove(transfer_data_collection,&transfer_data_collection[t_transfer_data_collection_pos],transfer_data_collection_pos-t_transfer_data_collection_pos);
	transfer_data_collection_pos=transfer_data_collection_pos-t_transfer_data_collection_pos;

	if( (uds_tranfer_data.remaining_data_len == 0 && transfer_data_collection_pos !=0 )
			|| ( uds_tranfer_data.remaining_data_len == transfer_data_collection_pos && uds_tranfer_data.remaining_data_len!=0))
	{
		memmove(temporary_flash_64bytes,(uint8_t*)(uintptr_t)uds_tranfer_data.current_address,64);
		memmove(temporary_flash_64bytes,transfer_data_collection,transfer_data_collection_pos);
		iso14229_ecu_flash_write(uds_tranfer_data.current_address, temporary_flash_64bytes, 64);
		uds_tranfer_data.remaining_data_len -= transfer_data_collection_pos;
		transfer_data_collection_pos = 0;
	}

	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	iso14229_1_temporary_buffer[1] = iso14229_1_received_indn.msg[1];
	uds_tranfer_data.sts = TD_ACTIVE;
	iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,2);
	return;
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_diagnostic_session_control()
{
	static uds_session_t *current_session = NULL;

	if(iso14229_1_received_indn.msg_sz != 2)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint8_t sub = iso14229_1_received_indn.msg[1] & 0x7Fu;
	uint8_t suppress = iso14229_1_received_indn.msg[1] & 0x80u;
	uint32_t list_sz = sizeof(uds_sessions)/sizeof(uds_session_t);

	session_status sts = A_NOT_EXISTS;

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_sessions[i].id == sub)
		{
			current_session = &uds_sessions[i];
			sts = uds_sessions[i].sts;
		}
	}

	if(sts == A_NOT_EXISTS || current_session == NULL)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SFNS);
		return;
	}
	else if(sts == A_LOCKED)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_CNC);
		return;
	}

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if((uds_sessions[i].sts & 0x0F) != 0)
			uds_sessions[i].sts = uds_sessions[i].default_sts == A_ACTIVE
			             ? A_INACTIVE : uds_sessions[i].default_sts;
	}

	uint32_t sa_list_sz = sizeof(uds_security_accesses)/sizeof(uds_security_access_t);

	for(register uint32_t i = 0;i<sa_list_sz;i++)
	{
		uds_security_accesses[i].sts = uds_security_accesses[i].default_sts;
	}


	current_session->sts = A_ACTIVE;

	if(current_session->on_opening != NULL)
		current_session->on_opening();

	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	iso14229_1_temporary_buffer[1] = sub;
	iso14229_1_temporary_buffer[2] = (current_session->timeout.max_response & 0xFF00) >> 8;
	iso14229_1_temporary_buffer[3] = (current_session->timeout.max_response & 0x00FF) >> 0;
	iso14229_1_temporary_buffer[4] = (current_session->timeout.time_limit & 0xFF00) >> 8;
	iso14229_1_temporary_buffer[5] = (current_session->timeout.time_limit & 0x00FF) >> 0;

	if(suppress == 0)
		iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,6);

	current_session->timeout.last_update = iso14229_getms();
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_diagnostic_session_refresh_timeout()
{
	uint32_t list_sz = sizeof(uds_sessions)/sizeof(uds_session_t);

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_sessions[i].sts == A_ACTIVE)
		{
			uds_sessions[i].timeout.last_update = iso14229_getms();
		}
	}
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_uds_srvc_ecu_reset()
{
	if(iso14229_1_received_indn.msg_sz != 2)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint8_t sub = iso14229_1_received_indn.msg[1] & 0x7Fu;
	uint8_t suppress = iso14229_1_received_indn.msg[1] & 0x80u;
	void (*reset_cb)() = NULL;

	switch(sub)
	{
	case 0x01:
		reset_cb = uds_ecu_reset.cb_HR;
		break;
	case 0x02:
		reset_cb = uds_ecu_reset.cb_KOFFONR;
		break;
	case 0x03:
		reset_cb = uds_ecu_reset.cb_SR;
		break;
	case 0x04:
		reset_cb = uds_ecu_reset.cb_ERPSD;
		break;
	case 0x05:
		reset_cb = uds_ecu_reset.cb_DRPSD;
		break;
	default:
		break;
	}

	if(reset_cb == NULL)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SFNS);
		return;
	}

	if(suppress == 0)
	{
		uds_server.s_msg = 0;
		uds_server.errn = 0;
		iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		iso14229_1_temporary_buffer[1] = sub;
		iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,2);
		iso15765_process(&uds_server.nl);
		uint32_t wait_start = iso14229_getms();
		do
		{
			osDelay(10);
		}
		while(uds_server.s_msg == 0 && uds_server.errn == 0
				&& (iso14229_getms() - wait_start) < 1000u);
	}

	reset_cb();
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

static uint8_t data_buffer_sz;
static uint8_t data_buffer[129];

void iso14229_srvc_read_data_by_localid()
{
	if( iso14229_1_received_indn.msg_sz < 3 || iso14229_1_received_indn.msg_sz%2!=1 )
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint32_t pos = 1;
	uint32_t tb_pos = 1;
	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);

	uint8_t is_fnr = iso14229_1_received_indn.n_ai.n_tt == N_TA_T_FUNC ? 1 : 0;

	while(pos < iso14229_1_received_indn.msg_sz)
	{
		uint16_t data_id = 	iso14229_1_received_indn.msg[pos]<<8 | iso14229_1_received_indn.msg[pos+1];
		pos+=2;

		volatile uds_read_data_by_id_t* current_local_id = NULL;

		uint32_t list_sz = sizeof(uds_read_data_by_id)/sizeof(uds_read_data_by_id_t);
		uint8_t session_valid = 0;
		uint8_t security_check = 0;

		for(register uint32_t i = 0;i<list_sz;i++)
		{
			if(uds_read_data_by_id[i].id == data_id && uds_read_data_by_id[i].id!=0)
			{
				current_local_id = &uds_read_data_by_id[i];
				break;
			}
		}

		if(current_local_id == NULL)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_ROOR);
			return;
		}

		if(current_local_id->fnr_enabled == 0 && is_fnr == 1)
		{
			return;
		}

		if(current_local_id->type == RDBID_AS_MEMORY_ADDRESS)
		{
			if((current_local_id->data.as_addr.size == 0 || current_local_id->data.as_addr.address == NULL))
			{
				iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
						__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC04);
				return;
			}
			else
			{
				if(current_local_id->data.as_addr.as_msb == 1)
				{
					for(int tc = 0;tc < current_local_id->data.as_addr.size; tc++)
					{
						data_buffer[tc] = *(((uint8_t*)current_local_id->data.as_addr.address)+current_local_id->data.as_addr.size-(tc+1));

					}
				}
				else
				{
					memmove(data_buffer,current_local_id->data.as_addr.address,current_local_id->data.as_addr.size);

				}
				data_buffer_sz = current_local_id->data.as_addr.size;
			}
		}
		else if(current_local_id->type == RDBID_AS_RETVAL_OF_FUNC)
		{
			if(current_local_id->data.as_func.func == NULL)
			{
				iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
						__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC04);
				return;
			}
			else
			{
				current_local_id->data.as_func.func(data_buffer,&data_buffer_sz,current_local_id->data.as_func.func_arg);
				if(data_buffer_sz == 0 || data_buffer_sz > 128)
				{
					iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
							__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC04);
					return;
				}
			}
		}
		else
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC04);
			return;
		}

		list_sz = sizeof(uds_sessions) / sizeof(uds_session_t);

		for(register uint32_t i = 0; i < list_sz; i++)
		{
			if(uds_sessions[i].id == current_local_id->session && uds_sessions[i].sts == A_ACTIVE)
				session_valid = 1;
		}

		if(session_valid == 0)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
			return;
		}

		uint32_t sa_list_sz = sizeof(uds_security_accesses)/sizeof(uds_security_access_t);

		for(register uint32_t j = 0;j<sa_list_sz;j++)
		{
			if(uds_security_accesses[j].access_lvl >= current_local_id->security_level && uds_security_accesses[j].sts == SA_ACTIVE)
				security_check = 1;
		}

		if(security_check == 0 && current_local_id->security_level != 0xFF)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SAD);
			return;
		}

		if((uint32_t)tb_pos + 2u + data_buffer_sz > sizeof(iso14229_1_temporary_buffer))
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_RTL);
			return;
		}

		iso14229_1_temporary_buffer[tb_pos] = (data_id & 0xFF00) >> 8;
		iso14229_1_temporary_buffer[tb_pos+1] = (data_id & 0x00FF) >> 0;

		tb_pos+=2;

		for(int k = 0;k< data_buffer_sz; k++)
		{
			iso14229_1_temporary_buffer[tb_pos+k] = data_buffer[k];
		}
		tb_pos+=data_buffer_sz;

	}
	iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,tb_pos );
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_srvc_write_data_by_localid()
{
	if( iso14229_1_received_indn.msg_sz < 3 )
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint32_t pos = 1;

	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);

	uint8_t is_fnr = iso14229_1_received_indn.n_ai.n_tt == N_TA_T_FUNC ? 1 : 0;


	uint16_t data_id = 	iso14229_1_received_indn.msg[pos]<<8 | iso14229_1_received_indn.msg[pos+1];
	pos+=2;

	volatile uds_write_data_by_id_t* current_local_id = NULL;

	uint32_t list_sz = sizeof(uds_write_data_by_id)/sizeof(uds_write_data_by_id_t);
	uint8_t session_valid = 0;
	uint8_t security_check = 0;

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_write_data_by_id[i].id == data_id && uds_write_data_by_id[i].id!=0)
		{
			current_local_id = &uds_write_data_by_id[i];
			break;
		}
	}

	if(current_local_id == NULL)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_ROOR);
		return;
	}

	if(current_local_id->fnr_enabled == 0 && is_fnr == 1)
	{
		return;
	}

	list_sz = sizeof(uds_sessions) / sizeof(uds_session_t);

	for(register uint32_t i = 0; i < list_sz; i++)
	{
		if(uds_sessions[i].id == current_local_id->session && uds_sessions[i].sts == A_ACTIVE)
			session_valid = 1;
	}

	if(session_valid == 0)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	uint32_t sa_list_sz = sizeof(uds_security_accesses)/sizeof(uds_security_access_t);

	for(register uint32_t j = 0;j<sa_list_sz;j++)
	{
		if(uds_security_accesses[j].access_lvl >= current_local_id->security_level && uds_security_accesses[j].sts == SA_ACTIVE)
			security_check = 1;
	}

	if(security_check == 0 && current_local_id->security_level != 0xFF)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SAD);
		return;
	}

	if(current_local_id->type == WRBID_AS_MEMORY_ADDRESS)
	{
		if(current_local_id->data.as_addr.address == NULL)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC04);
			return;
		}

		switch(current_local_id->data.as_addr.type)
		{
		case VAR_TYPE_U8:
		case VAR_TYPE_I8:
		case VAR_TYPE_ARR:
			memmove(current_local_id->data.as_addr.address,(iso14229_1_received_indn.msg + 3),iso14229_1_received_indn.msg_sz - 3);
			break;
		case VAR_TYPE_U16:
		case VAR_TYPE_I16:
			if(iso14229_1_received_indn.msg_sz < 5)
			{
				iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
						__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_IMLOIF);
				return;
			}
			*((uint16_t*)current_local_id->data.as_addr.address) = (uint16_t)uds_load_be(iso14229_1_received_indn.msg + 3, 2);
			break;
		case VAR_TYPE_U32:
		case VAR_TYPE_I32:
			if(iso14229_1_received_indn.msg_sz < 7)
			{
				iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
						__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_IMLOIF);
				return;
			}
			*((uint32_t*)current_local_id->data.as_addr.address) = uds_load_be(iso14229_1_received_indn.msg + 3, 4);
			break;
		default:
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC04);
			return;
		}
	}
	else if(current_local_id->type == WRBID_AS_RETVAL_OF_FUNC)
	{
		if(current_local_id->data.as_func.func == NULL)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC04);
			return;
		}

		if(current_local_id->data.as_func.size!=0 && current_local_id->data.as_func.size != (uint32_t)(iso14229_1_received_indn.msg_sz - 3))
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_IMLOIF);
			return;
		}

		if(current_local_id->data.as_func.func(iso14229_1_received_indn.msg + 3,iso14229_1_received_indn.msg_sz - 3,current_local_id->data.as_func.func_arg) != 0)
		{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
					__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC05);
			return;
		}
	}
	else
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg), UDS_NRC_VMSCNC04);
		return;
	}

	iso14229_1_temporary_buffer[1] = (data_id & 0xFF00) >> 8;
	iso14229_1_temporary_buffer[2] = (data_id & 0x00FF) >> 0;

	iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,3 );
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_read_memory_by_address()
{
	if( iso14229_1_received_indn.msg_sz < 4)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint8_t mem_addr_sz = iso14229_1_received_indn.msg[1] & 0x0Fu;
	uint8_t mem_sz_sz = (uint8_t)((iso14229_1_received_indn.msg[1] & 0xF0u) >> 4);

	if(mem_addr_sz < 1 || mem_addr_sz > 4 || mem_sz_sz < 1 || mem_sz_sz > 4
			|| iso14229_1_received_indn.msg_sz != (uint16_t)(2u + mem_addr_sz + mem_sz_sz))
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint32_t mem_address = uds_load_be(&iso14229_1_received_indn.msg[2], mem_addr_sz);
	uint32_t mem_sz = uds_load_be(&iso14229_1_received_indn.msg[2 + mem_addr_sz], mem_sz_sz);

	if(mem_sz == 0 || mem_sz > 0xFF)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	for(uint32_t i=0;i<mem_sz;i++)
		iso14229_1_temporary_buffer[1+i] = *((uint8_t*)(uintptr_t)(mem_address + i));

	iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,(uint16_t)(1u + mem_sz));
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_uds_srvc_request_download()
{
	if(iso14229_1_received_indn.msg_sz < 4)
	{
		uds_tranfer_data.sts = TD_LOCKED;
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	if(__uds_get_subfunction(iso14229_1_received_indn.msg) != 0x00)
	{
		uds_tranfer_data.sts = TD_LOCKED;
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	uint32_t sa_list_sz = sizeof(uds_security_accesses)/sizeof(uds_security_access_t);
	uint8_t security_check = 0;

	for(register uint32_t j = 0;j<sa_list_sz;j++)
	{
		if(uds_security_accesses[j].sts == SA_ACTIVE &&
				uds_security_accesses[j].access_lvl >= uds_download_request.security_level)
			security_check = 1;
	}

	if(security_check == 0 && uds_download_request.security_level != 0xFF)
	{
		uds_tranfer_data.sts = TD_LOCKED;
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SAD);
		return;
	}


	uint8_t bcnt_mem_sz = (iso14229_1_received_indn.msg[2] & 0xF0) >> 4;
	uint8_t bcnt_mem_addr = (iso14229_1_received_indn.msg[2] & 0x0F) >> 0;

	if(bcnt_mem_sz > 4 || bcnt_mem_addr > 4 || bcnt_mem_sz < 1 ||  bcnt_mem_addr < 3)
	{
		uds_tranfer_data.sts = TD_LOCKED;
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	if(iso14229_1_received_indn.msg_sz != (uint16_t)(3u + bcnt_mem_addr + bcnt_mem_sz))
	{
		uds_tranfer_data.sts = TD_LOCKED;
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uds_download_request.memory_address = uds_load_be(&iso14229_1_received_indn.msg[3], bcnt_mem_addr);
	uds_download_request.memory_sz = uds_load_be(&iso14229_1_received_indn.msg[3 + bcnt_mem_addr], bcnt_mem_sz);

	if(uds_download_request.memory_sz == 0)
	{
		uds_tranfer_data.sts = TD_LOCKED;
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	transfer_data_collection_pos = 0;
	memset(transfer_data_collection,0,UDS_TDC_SZ);
	uds_tranfer_data.sts = TD_INACTIVE;
	uds_tranfer_data.block_counter = 1;
	uds_tranfer_data.current_address = uds_download_request.memory_address;
	uds_tranfer_data.remaining_data_len = uds_download_request.memory_sz;
	uds_tranfer_data.expected_data_len = uds_download_request.memory_sz;
	uds_tranfer_data.calculated_crc = 0xFFFF;
	uds_download_request.sts = RD_ACTIVE;

	static uint8_t t_buffer[4];

	t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	t_buffer[1] = 0x20;
	t_buffer[2] = 0x02;
	t_buffer[3] = 0x00;
	iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,4);
	return;
}

/******************************************************************************
* EOF - NO CODE AFTER THIS LINE
******************************************************************************/
#endif
