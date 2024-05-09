/*!
@file   iso14229_1.c
@brief  Source file of the ISO14229-1 library
@t.odo	-
---------------------------------------------------------------------------
MIT License
Copyright (c) 2020 Io. D (Devcoons.com)
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
#include "rng.h"

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
	{.sid = UDS_SRVC_ClearDiagnosticInformation, 		.is_supported = iso14229_1_NO },
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
static __attribute__ ((section(".buffers")))
					uint32_t transfer_data_collection_pos =  0;
static __attribute__ ((section(".buffers")))
					uint32_t iso14229_1_timeout_extra_time = 0;

/******************************************************************************
* Declaration | Static Functions
******************************************************************************/

static void indn(n_indn_t* info);
static void on_error(n_rslt err_type);

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
	uds_server.nl.fr_id_type = CBUS_ID_T_EXTENDED,
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

	uint16_t dtr_crc = (iso14229_1_received_indn.msg[1] << 8) |  iso14229_1_received_indn.msg[2];
	uint32_t dtr_len =   (iso14229_1_received_indn.msg[3] << 24) | (iso14229_1_received_indn.msg[4]<<16) | (iso14229_1_received_indn.msg[5] << 8) |  iso14229_1_received_indn.msg[6];

	if(dtr_crc == uds_tranfer_data.calculated_crc && dtr_len == uds_tranfer_data.expected_data_len)
	{
		uint8_t t_buffer[2];
		t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		t_buffer[1] = iso14229_1_received_indn.msg[1];
		uds_tranfer_data.sts = uds_tranfer_data.default_sts;
		uds_download_request.sts = uds_download_request.default_sts;
		iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);
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
	if(h->ptr_iocontrol != h->ptr_inactive && h->ptr_iocontrol != (uint32_t)&h->out_val)
	{
		return h->ptr_inactive;
	}
	return h->ptr_iocontrol;
}


void iso14229_1_srvc_input_output_control_process()
{
	uint32_t sessions_list_sz = sizeof(uds_sessions) / sizeof(uds_session_t);
	uint32_t session_valid = -1;
	for(register uint32_t i = 0; i < sessions_list_sz; i++)
	{
		if(uds_sessions[i].sts == A_ACTIVE)
			session_valid = i;
	}

	if(session_valid == -1)
		return;

	uint32_t list_sz = sizeof(uds_io_control_by_id)/sizeof(uds_io_control_by_id_t*);

	iocontrol_status sts =  RTN_INACTIVE;

	for(register uint32_t i = 0;i<list_sz;i++)
	{

		if(uds_io_control_by_id[i]->sts == IOC_ACTIVE && uds_io_control_by_id[i]->session != uds_sessions[session_valid].id)
		{
			uds_io_control_by_id[i]->ptr_iocontrol = uds_io_control_by_id[i]->ptr_inactive;
			///RESET CONTROL TO MATLAB

			uds_io_control_by_id[i]->sts = IOC_INACTIVE;

		}
	}
}
/* --- ClearDiagnosticInformation (ref:iso14229-1) Cap 12.2 p223----*/
void iso14229_1_srvc_ClearDiagnosticInformation()
{
	//Minimum lenght check
	if(iso14229_1_received_indn.msg_sz >= 4)  //pag 226
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint32_t groupOfDtc = 0x00 <<24 | iso14229_1_received_indn.msg[1]<<16 | iso14229_1_received_indn.msg[2]<<8|iso14229_1_received_indn.msg[3];

	if(groupOfDtc != 0x00FFFFFF) //GODTC_supported ?
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
				return;
	}



}
/* --- readDTCinformation (ref:iso14229-1) Cap 12.3 p22----------- */
void iso14229_1_srvc_readDTCinformation()
{
	//Minimum lenght check
	if(iso14229_1_received_indn.msg_sz < 3)  //pag 301
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
		return;
	}

	uint8_t req_type = __uds_get_subfunction(iso14229_1_received_indn.msg);


	switch(req_type)
		{
			case UDS_RDTC_RNODTCBSM:/* rep.Num.OfDTCByStatusMask		 */
				iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg); //SID +0x40
				iso14229_1_temporary_buffer[1] = UDS_RDTC_RNODTCBSM;
				iso14229_1_temporary_buffer[2] = iso14229_1_received_indn.msg[2];									//id
				iso14229_1_temporary_buffer[3] = iso14229_1_received_indn.msg[3];									//id
				iso14229_1_temporary_buffer[4] = iso14229_1_received_indn.msg[4];
				break;
			case UDS_RDTC_RDTCBSM: /* rep.DTCByStatusMask			 */
				break;
			default://Not Supported

				break;

		}




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

		if(uds_io_control_by_id[i]->id == data_id && uds_io_control_by_id[i]->id != 0)
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
	if (ioc_param >= 0x04)// ISOSAERESRVD
	{
			iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
			return;
	}
	current_iocontrol->sts = IOC_ACTIVE;
	//
	if(current_iocontrol->var_type == VAR_TYPE_u8 || current_iocontrol->var_type == VAR_TYPE_i8)
		current_iocontrol->out_val = iso14229_1_received_indn.msg[4];
	else if(current_iocontrol->var_type == VAR_TYPE_u16 || current_iocontrol->var_type == VAR_TYPE_i16)
		current_iocontrol->out_val = iso14229_1_received_indn.msg[4]<<8 | iso14229_1_received_indn.msg[5];
	else if(current_iocontrol->var_type == VAR_TYPE_u32 || current_iocontrol->var_type == VAR_TYPE_i32)
		current_iocontrol->out_val = iso14229_1_received_indn.msg[4]<<24 | iso14229_1_received_indn.msg[5]<<16 | iso14229_1_received_indn.msg[6]<<8 | iso14229_1_received_indn.msg[7];

	switch(ioc_param)
	{
		case 00://RCTECU - returnControlToECU
			current_iocontrol->ptr_iocontrol = current_iocontrol->ptr_inactive;
			current_iocontrol->sts = IOC_INACTIVE;
			break;
		case 01: //RTD - resetToDefault
			break;
		case 02://FCS - freezeCurrentState
			break;
		case 03://STA - shortTermAdjustment
			current_iocontrol->ptr_iocontrol = (intptr_t)&current_iocontrol->out_val;
			current_iocontrol->sts = IOC_ACTIVE;
			break;
	}
	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg); //SID +0x40
	iso14229_1_temporary_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);				//0x2F
	iso14229_1_temporary_buffer[2] = iso14229_1_received_indn.msg[2];									//id
	iso14229_1_temporary_buffer[3] = iso14229_1_received_indn.msg[3];									//id
	iso14229_1_temporary_buffer[4] = iso14229_1_received_indn.msg[4];									//val

	iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,5);

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
	uint16_t routine_cmd = iso14229_1_received_indn.msg[1];
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

	uint8_t rslt = current_routine->rountine((void*)current_routine,routine_cmd,routine_args,routing_args_sz);

	if(rslt == 0)
	{

		iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		iso14229_1_temporary_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
		iso14229_1_temporary_buffer[2] = iso14229_1_received_indn.msg[2];
		iso14229_1_temporary_buffer[3] = iso14229_1_received_indn.msg[3];
		iso14229_1_temporary_buffer[4] = rslt;
		if(current_routine->rst != NULL && current_routine->rst_sz !=0)
			memmove(&iso14229_1_temporary_buffer[5],current_routine->rst,current_routine->rst_sz);

		iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,5+current_routine->rst_sz);
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
	uint8_t req_type = (__uds_get_subfunction(iso14229_1_received_indn.msg) & 0x01);

	uint8_t req_sa_lvl  = req_type == 1
			? (__uds_get_subfunction(iso14229_1_received_indn.msg) ) : (__uds_get_subfunction(iso14229_1_received_indn.msg) - 0x01);

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
		if(inc_delay > 5)
		{
			if( (last_trial_time + (60*60*1000)) > xTaskGetTickCount() )
			{
				last_trial_time = xTaskGetTickCount();
				iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RTDNE);
				return;
			}
		}
		else
		{
			if((last_trial_time + inc_delay*2000) > xTaskGetTickCount())
			{
				last_trial_time = xTaskGetTickCount();
				iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RTDNE);
				return;
			}
		}
	}

	static uint8_t t_buffer[6];

	if(current_sa->sts == SA_ACTIVE && req_type == 0x01)
	{
		t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
		t_buffer[2] = 0;
		t_buffer[3] = 0;
		t_buffer[4] = 0;
		t_buffer[5] = 0;
		iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,6);
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
		HAL_RNG_GenerateRandomNumber(&hrng, &current_sa->current_seed);
		t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
		t_buffer[2] = (current_sa->current_seed & 0xFF000000) >> 24;
		t_buffer[3] = (current_sa->current_seed & 0x00FF0000) >> 16;
		t_buffer[4] = (current_sa->current_seed & 0x0000FF00) >> 8;
		t_buffer[5] = (current_sa->current_seed & 0x000000FF) >> 0;
		iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,6);
		break;

	case 0x00:
		key = current_sa->key_validation != NULL ? current_sa->key_validation(current_sa->current_seed) : current_sa->current_seed;
		resp_key = ((uint32_t)iso14229_1_received_indn.msg[2] << 24);
		resp_key |= ((uint32_t)iso14229_1_received_indn.msg[3] << 16);
		resp_key |= ((uint32_t)iso14229_1_received_indn.msg[4] << 8);
		resp_key += iso14229_1_received_indn.msg[5];

		if(key == resp_key)
		{
			for(register uint32_t i = 0;i<list_sz;i++)
			{
				uds_security_accesses[i].sts = uds_security_accesses[i].default_sts;
			}
			last_trial_time = 0;
			inc_delay=0;
			current_sa->sts = SA_ACTIVE;
			t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
			t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
			iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);
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

	if(__uds_get_subfunction(iso14229_1_received_indn.msg) != 0)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_SFNS);
		return;
	}

	static uint8_t t_buffer[2];

	t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
	iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);

	iso14229_1_srvc_diagnostic_session_refresh_timeout();
}

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

void iso14229_1_srvc_tranfer_data()
{
	if((uds_tranfer_data.sts != TD_INACTIVE && uds_tranfer_data.sts!=TD_ACTIVE)
			|| ((uds_tranfer_data.block_counter != (uint32_t)(iso14229_1_received_indn.msg[1]+1)
			&& (uds_tranfer_data.block_counter == 0xff && iso14229_1_received_indn.msg[1] != 0x01)
			&& (uds_tranfer_data.sts == TD_INACTIVE && iso14229_1_received_indn.msg[1] != 0x01)) ))
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RSE);
		return;
	}

	if( (iso14229_1_received_indn.msg_sz < 3) || ((iso14229_1_received_indn.msg_sz - 2) > 0x200) )
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_RSE);
		return;
	}
	uds_tranfer_data.block_counter = iso14229_1_received_indn.msg[1];
	memmove(&transfer_data_collection[transfer_data_collection_pos], &iso14229_1_received_indn.msg[2],iso14229_1_received_indn.msg_sz - 2);
	transfer_data_collection_pos += iso14229_1_received_indn.msg_sz - 2;

	uds_tranfer_data.calculated_crc = crc16_ccitt(uds_tranfer_data.calculated_crc, &iso14229_1_received_indn.msg[2], iso14229_1_received_indn.msg_sz - 2);

	uint32_t t_transfer_data_collection_pos = 0;

	if(uds_tranfer_data.current_address % 0x20 != 0)
	{
		uint8_t diff = uds_tranfer_data.current_address % 0x20;

		uds_tranfer_data.current_address -= diff;
		memmove(&transfer_data_collection[diff],transfer_data_collection,transfer_data_collection_pos);
		memmove(transfer_data_collection,(uint32_t*)uds_tranfer_data.current_address,diff);
		uds_tranfer_data.remaining_data_len+=diff;
		transfer_data_collection_pos += diff;
	}

	for(uint32_t i=0;i<(transfer_data_collection_pos-(transfer_data_collection_pos%64));i+=64)
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
		memmove(temporary_flash_64bytes,(uint32_t*)uds_tranfer_data.current_address,64);
		memmove(temporary_flash_64bytes,transfer_data_collection,transfer_data_collection_pos);
		iso14229_ecu_flash_write(uds_tranfer_data.current_address, temporary_flash_64bytes, 64);
		uds_tranfer_data.remaining_data_len -= transfer_data_collection_pos;
		transfer_data_collection_pos = 0;
	}
	static uint8_t t_buffer[2];
	t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	t_buffer[1] = iso14229_1_received_indn.msg[1];
	uds_tranfer_data.sts = TD_ACTIVE;
	iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);
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

	uint32_t list_sz = sizeof(uds_sessions)/sizeof(uds_session_t);

	session_status sts = A_NOT_EXISTS;

	for(register uint32_t i = 0;i<list_sz;i++)
	{
		if(uds_sessions[i].id == __uds_get_subfunction(iso14229_1_received_indn.msg))
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

	static uint8_t t_buffer[6];
	t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
	t_buffer[2] = (current_session->timeout.max_response & 0xFF00) >> 8;
	t_buffer[3] = (current_session->timeout.max_response & 0x00FF) >> 0;
	t_buffer[4] = (current_session->timeout.time_limit & 0xFF00) >> 8;
	t_buffer[5] = (current_session->timeout.time_limit & 0x00FF) >> 0;

	iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,6);

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

	static uint8_t t_buffer[2];

	switch(__uds_get_subfunction(iso14229_1_received_indn.msg))
	{
	case 0x01:
		if(uds_ecu_reset.cb_HR == NULL)
			break;
		uds_server.s_msg = 0;
		uds_server.errn = 0;
		t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
		iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);
		iso15765_process(&uds_server.nl);
		do
		{
			osDelay(10);
		}
		while(uds_server.s_msg == 0 && uds_server.errn == 0);
		uds_ecu_reset.cb_HR();
		return;
	case 0x02:
		if(uds_ecu_reset.cb_KOFFONR == NULL)
			break;
		uds_server.s_msg = 0;
		uds_server.errn = 0;
		t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
		iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);
		iso15765_process(&uds_server.nl);
		do
		{
			osDelay(10);
		}
		while(uds_server.s_msg == 0 && uds_server.errn == 0);

		uds_ecu_reset.cb_KOFFONR();
		return;
	case 0x03:
		if(uds_ecu_reset.cb_SR == NULL)
			break;
		uds_server.s_msg = 0;
		uds_server.errn = 0;
		t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
		iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);
		iso15765_process(&uds_server.nl);
		do
		{
			osDelay(10);
		}
		while(uds_server.s_msg == 0 && uds_server.errn == 0);
		uds_ecu_reset.cb_SR();
		return;
	case 0x04:
		if(uds_ecu_reset.cb_ERPSD == NULL)
			break;
		uds_server.s_msg = 0;
		uds_server.errn = 0;
		t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
		iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);
		iso15765_process(&uds_server.nl);
		do
		{
			osDelay(10);
		}
		while(uds_server.s_msg == 0 && uds_server.errn == 0);
		uds_ecu_reset.cb_ERPSD();
		return;
	case 0x05:
		if(uds_ecu_reset.cb_DRPSD == NULL)
			break;
		uds_server.s_msg = 0;
		uds_server.errn = 0;
		t_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
		t_buffer[1] = __uds_get_subfunction(iso14229_1_received_indn.msg);
		iso14229_send(&iso14229_1_received_indn.n_ai,t_buffer,2);
		iso15765_process(&uds_server.nl);
		do
		{
			osDelay(10);
		}
		while(uds_server.s_msg == 0 && uds_server.errn == 0);
		uds_ecu_reset.cb_DRPSD();
		return;

	default:
		break;
	}

	iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
			__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_IMLOIF);
	return;
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

static uint8_t data_buffer_sz;
static uint8_t data_buffer[129];

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
		switch(current_local_id->data.as_addr.type)
		{
		case VAR_TYPE_u8:
		case VAR_TYPE_i8:
		case VAR_TYPE_arr:
			memmove(current_local_id->data.as_addr.address,(iso14229_1_received_indn.msg + 3),iso14229_1_received_indn.msg_sz - 3);
			break;
		case VAR_TYPE_u16:
		case VAR_TYPE_i16:
			(*((uint16_t*)current_local_id->data.as_addr.address)) = ((uint16_t)(*(uint8_t*)(iso14229_1_received_indn.msg + 3))) << 8 |  ((uint16_t)(*(uint8_t*)(iso14229_1_received_indn.msg + 4)));
			break;
		case VAR_TYPE_u32:
		case VAR_TYPE_i32:
			(*((uint32_t*)current_local_id->data.as_addr.address)) = ((uint32_t)(*(uint8_t*)(iso14229_1_received_indn.msg + 3))) << 24
																	|  ((uint32_t)(*(uint8_t*)(iso14229_1_received_indn.msg + 4))) << 16
																	|  ((uint32_t)(*(uint8_t*)(iso14229_1_received_indn.msg + 5))) << 8
																	|  ((uint32_t)(*(uint8_t*)(iso14229_1_received_indn.msg + 6))) ;
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

		if(current_local_id->data.as_func.size!=0 && current_local_id->data.as_func.size != iso14229_1_received_indn.msg_sz - 3)
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

	uint8_t mem_addr_sz = __uds_get_subfunction(iso14229_1_received_indn.msg) & 0x0F;
	uint8_t mem_sz_sz = (__uds_get_subfunction(iso14229_1_received_indn.msg) & 0xF0) >> 4;

	uint64_t mem_address = 0;
	for(int i=0; i<mem_addr_sz; i++)
		mem_address |= (iso14229_1_received_indn.msg[2+i]) << (((mem_addr_sz-1)-i)*8);

	uint32_t mem_sz = 0;
	for(int i=0; i<mem_sz_sz; i++)
		mem_sz |= (iso14229_1_received_indn.msg[2+mem_addr_sz+i]) << (((mem_sz_sz-1)-i)*8);

	if(mem_sz > 0xFF)
	{
		iso14229_send_NRC(&iso14229_1_received_indn.n_ai,
				__uds_get_function(iso14229_1_received_indn.msg),UDS_NRC_ROOR);
		return;
	}

	iso14229_1_temporary_buffer[0] = __uds_get_function_positive_response(iso14229_1_received_indn.msg);
	for(uint32_t i=0;i<mem_sz;i++)
		iso14229_1_temporary_buffer[1+i] = *((uint8_t*)((intptr_t)(mem_address+i)));

	iso14229_send(&iso14229_1_received_indn.n_ai,iso14229_1_temporary_buffer,1+mem_sz);
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

	uds_download_request.memory_address = 0;
	for(int i=0; i<bcnt_mem_addr; i++)
		uds_download_request.memory_address |= (iso14229_1_received_indn.msg[3+i]) << (((bcnt_mem_addr-1)-i)*8);

	uds_download_request.memory_sz = 0;
	for(int i=0; i<bcnt_mem_sz; i++)
		uds_download_request.memory_sz |= (iso14229_1_received_indn.msg[(3+bcnt_mem_addr)+i]) << (((bcnt_mem_sz-1)-i)*8);

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
