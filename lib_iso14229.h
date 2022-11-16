/*!
@file   iso14229_1.h
@brief  Header file of the ISO14229-1 library
@t.odo	-
---------------------------------------------------------------------------
MIT License
Copyright (c) 2020 Io. D (Devcoons.com)
Developed for: Energica Motor Company SpA
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

#ifndef DEVCOONS_ISO14229_1_H_
#define DEVCOONS_ISO14229_1_H_

/******************************************************************************
* Includes
******************************************************************************/

#include <stdlib.h>
#include <stdint.h>
#include "lib_iso15765.h"
#include "lib_iso14229_config.h"
#include "lib_crypto.h"

#define UDS_TDC_SZ 512*2*2

#define __uds_get_function(x) x[0]
#define __uds_get_subfunction(x) x[1]
#define __uds_get_function_positive_response(x) x[0]+0x40

/* -- UDS Supported Services [ ISO14229-1-2020 p.39 ]			  	      -- */

#define UDS_SRVC_DiagnosticSessionControl			0x10
#define UDS_SRVC_ECUReset							0x11
#define UDS_SRVC_SecurityAccess						0x27
#define UDS_SRVC_CommunicationControl				0x28
#define UDS_SRVC_TesterPresent						0x3E
#define UDS_SRVC_Authentication						0x29
#define UDS_SRVC_SecuredDataTransmission			0x84
#define UDS_SRVC_ControlDTCSetting					0x85
#define UDS_SRVC_ResponseOnEvent					0x86
#define UDS_SRVC_LinkControl						0x87
#define UDS_SRVC_ReadDataByIdentifier				0x22
#define UDS_SRVC_ReadMemoryByAddress				0x23
#define UDS_SRVC_ReadScalingDataByIdentifier		0x24
#define UDS_SRVC_ReadDataByPeriodicIdentifier		0x2A
#define UDS_SRVC_DynamicallyDefineDataIdentifier	0x2C
#define UDS_SRVC_WriteDataByIdentifier				0x2E
#define UDS_SRVC_WriteMemoryByAddress				0x3D
#define UDS_SRVC_ClearDiagnosticInformation			0x14
#define UDS_SRVC_ReadDTCInformation					0x19
#define UDS_SRVC_InputOutputControlByIdentifier		0x2F
#define UDS_SRVC_RoutineControl						0x31
#define UDS_SRVC_RequestDownload					0x34
#define UDS_SRVC_RequestUpload						0x35
#define UDS_SRVC_TransferData						0x36
#define UDS_SRVC_RequestTransferExit				0x37
#define UDS_SRVC_RequestFileTransfer				0x38

/* -- UDS Supported Diagnostic Sessions [ ISO14229-1-2020 p.40 ] 		  -- */

#define UDS_DIAG_DS 		0x01	/* defaultSession						 */
#define UDS_DIAG_PRGS 		0x02	/* ProgrammingSession           		 */
#define UDS_DIAG_EXTDS 		0x03	/* extendedDiagnosticSession    		 */
#define UDS_DIAG_SSDS 		0x04	/* safetySystemDiagnosticSession		 */
#define UDS_DIAG_VMS(x) 	0x40+x	/* vM.Specific x>=0 && x<=31			 */
#define UDS_DIAG_SSS(x) 	0x60+x	/* sS.Specific x>=0 && x<=31			 */

/* -- Negative Response Code (NRC) definition [ ISO14229-1-2020 p.390 ]	  -- */

#define UDS_NRC_GR 		    0x10	/* generalReject             		  	 */
#define UDS_NRC_SNS 		0x11	/* serviceNotSupported             		 */
#define UDS_NRC_SFNS 		0x12	/* SubFunctionNotSupported             	 */
#define UDS_NRC_IMLOIF 		0x13	/* incorrectMessageLengthOrInvalidFormat */
#define UDS_NRC_RTL 		0x14	/* responseTooLong             			 */
#define UDS_NRC_BRR 		0x21	/* busyRepeatRequest             		 */
#define UDS_NRC_CNC 		0x22	/* conditionsNotCorrect             	 */
#define UDS_NRC_RSE 		0x24	/* requestSequenceError             	 */
#define UDS_NRC_NRFSC 		0x25	/* noResponseFromSubnetComponent		 */
#define UDS_NRC_FPEORA 		0x26	/* FailurePreventsExecutionOfReq.Action	 */
#define UDS_NRC_ROOR 		0x31	/* requestOutOfRange             		 */
#define UDS_NRC_SAD 		0x33	/* securityAccessDenied             	 */
#define UDS_NRC_AR 			0x34	/* authenticationRequired             	 */
#define UDS_NRC_IK 			0x35	/* invalidKey             				 */
#define UDS_NRC_ENOA 		0x36	/* exceedNumberOfAttempts             	 */
#define UDS_NRC_RTDNE 		0x37	/* requiredTimeDelayNotExpired           */
#define UDS_NRC_SDTR 		0x38	/* secureDataTransmissionRequired		 */
#define UDS_NRC_SDTNA 		0x39	/* secureDataTransmissionNotAllowed		 */
#define UDS_NRC_SDTF 		0x3A	/* secureDataVerificationFailed			 */
#define UDS_NRC_CVFITP 		0x50	/* Cert. vrf. fld. inv. Time Period      */
#define UDS_NRC_CVFISI 		0x51	/* Cert. vrf. fld. inv. Signature	     */
#define UDS_NRC_CVFICOT 	0x52	/* Cert. vrf. fld. inv. Chain of Trust	 */
#define UDS_NRC_CVFIT 		0x53	/* Cert. verif. failed. Inv. Type		 */
#define UDS_NRC_CVFIF 		0x54	/* Cert. verif. failed. Inv. Format		 */
#define UDS_NRC_CVFICO 		0x55	/* Cert. verif. failed. Inv. Content	 */
#define UDS_NRC_CVFISC 		0x56	/* Cert. verif. failed. Inv. Scope		 */
#define UDS_NRC_CVFICE 		0x57	/* Cert. verif. failed. Inv. Cert.(rvk)	 */
#define UDS_NRC_OVF 		0x58	/* Ownership verification failed		 */
#define UDS_NRC_CCF 		0x59	/* Challenge calculation failed			 */
#define UDS_NRC_SARF 		0x5A	/* Setting Access Rights failed			 */
#define UDS_NRC_SKCDF 		0x5B	/* Session key cr/tn-deri/vtion failed	 */
#define UDS_NRC_CDUF 		0x5C	/* Configuration data usage failed		 */
#define UDS_NRC_DAF 		0x5D	/* DeAuthentication failed             	 */
#define UDS_NRC_UDNA 		0x70	/* uploadDownloadNotAccepted             */
#define UDS_NRC_TDS 		0x71	/* transferDataSuspended             	 */
#define UDS_NRC_GPF 		0x72	/* generalProgrammingFailure             */
#define UDS_NRC_WBSC 		0x73	/* wrongBlockSequenceCounter             */
#define UDS_NRC_RCRRP 		0x78	/* req.Received-Resp.Pending             */
#define UDS_NRC_SFNSIAS 	0x7E	/* SubFunc. NotSupp. In Actv.Session     */
#define UDS_NRC_SNSIAS 		0x7F	/* serviceNotSupportedInActiveSession	 */
#define UDS_NRC_RPMTH 		0x81	/* rpmTooHigh             				 */
#define UDS_NRC_RPMTL 		0x82	/* rpmTooLow             				 */
#define UDS_NRC_EIR 		0x83	/* engineIsRunning             			 */
#define UDS_NRC_EINR 		0x84	/* engineIsNotRunning             		 */
#define UDS_NRC_ERTTL 		0x85	/* engineRunTimeTooLow             		 */
#define UDS_NRC_TEMPTH 		0x86	/* temperatureTooHigh             		 */
#define UDS_NRC_TEMPTL 		0x87	/* temperatureTooLow             		 */
#define UDS_NRC_VSTH 		0x88	/* vehicleSpeedTooHigh             		 */
#define UDS_NRC_VSTL 		0x89	/* vehicleSpeedTooLow             		 */
#define UDS_NRC_TPTH 		0x8A	/* throttle/PedalTooHigh             	 */
#define UDS_NRC_TPTL 		0x8B	/* throttle/PedalTooLow             	 */
#define UDS_NRC_TRNIN 		0x8C	/* transmissionRangeNotInNeutral		 */
#define UDS_NRC_TRNIG 		0x8D	/* transmissionRangeNotInGear            */
#define UDS_NRC_BSNC 		0x8F	/* brakeSwitch(es)NotClosed              */
#define UDS_NRC_SLNIP 		0x90	/* shifterLeverNotInPark             	 */
#define UDS_NRC_TCCL 		0x91	/* torqueConverterClutchLocked           */
#define UDS_NRC_VTH 		0x92	/* voltageTooHigh             			 */
#define UDS_NRC_VTL 		0x93	/* voltageTooLow             			 */
#define UDS_NRC_RTNA 		0x94	/* ResourceTemporarilyNotAvailable		 */
									/* Internal Flash Invalid CRC            */
#define UDS_NRC_VMSCNC00 	0xF0	/* vehicleManufacturerSpecificErrorCode	 */
									/* Invalid Firmware Start Bytes          */
#define UDS_NRC_VMSCNC01 	0xF1	/* vehicleManufacturerSpecificErrorCode	 */
									/* Invalid Firmware Properties Space     */
#define UDS_NRC_VMSCNC02 	0xF2	/* vehicleManufacturerSpecificErrorCode	 */
									/* Error Validating Firmware Properties  */
#define UDS_NRC_VMSCNC03 	0xF3	/* vehicleManufacturerSpecificErrorCode  */
									/* Value is empty                        */
#define UDS_NRC_VMSCNC04 	0xF4	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC05 	0xF5	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC06	0xF6	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC07 	0xF7	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC08 	0xF8	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC09 	0xF9	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC10 	0xFA	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC11 	0xFB	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC12 	0xFC	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC13 	0xFD	/* vehicleManufacturerSpecificErrorCode  */
									/* ?                                     */
#define UDS_NRC_VMSCNC14 	0xFE	/* vehicleManufacturerSpecificErrorCode  */

/* -- Transmission Mode [ ISO14229-1-2020 p.421 ]			              -- */

#define UDS_TMD_SASR 		0x01	/* sendAtSlowRate    				     */
#define UDS_TMD_SAMR 		0x02	/* sendAtMediumRate    				     */
#define UDS_TMD_SAFR 		0x03	/* sendAtFastRate    				     */
#define UDS_TMD_SS 			0x04	/* stopSending    				         */

/* -- DTC Retrieve SubFunction [ ISO14229-1-2020 p.227 ]		          -- */

#define UDS_RDTC_RNODTCBSM 			0x01   /* rep.Num.OfDTCByStatusMask		 */
#define UDS_RDTC_RDTCBSM 			0x02   /* rep.DTCByStatusMask			 */
#define UDS_RDTC_RDTCSSI  			0x03   /* rep.DTCSn/t Identification	 */
#define UDS_RDTC_RDTCSSBDTC  		0x04   /* rep.DTCSn/t Rec. ByDTCNum	     */
#define UDS_RDTC_RDTCSDBRN  		0x05   /* rep.DTCStored DtByRec.Num      */
#define UDS_RDTC_RDTCEDRBDN  		0x06   /* rep.DTCExt DtRec.ByDTCNumber	 */
#define UDS_RDTC_RNODTCBSMR  		0x07   /* rep.Num.OfDTCBySvrt.MaskRec. 	 */
#define UDS_RDTC_RDTCBSMR  			0x08   /* rep.DTCBySeverityMaskRecord	 */
#define UDS_RDTC_RSIODTC  			0x09   /* rep.SeverityInformationOfDTC	 */
#define UDS_RDTC_RSUPDTC  			0x0A   /* rep.SupportedDTC			     */
#define UDS_RDTC_RFTFDTC  			0x0B   /* rep.FirstTestFailedDTC		 */
#define UDS_RDTC_RMRTFDTC  			0x0D   /* rep.MostRecentTestFailedDTC	 */
#define UDS_RDTC_RFCDTC 			0x0C   /* rep.FirstConfirmedDTC			 */
#define UDS_RDTC_RMRCDTC  			0x0E   /* rep.MostRecentConfirmedDTC	 */
#define UDS_RDTC_RDTCFDC  			0x14   /* rep.DTCFaultDetection-Counter	 */
#define UDS_RDTC_RDTCWPS  			0x15   /* rep.DTCWithPermanentStatus	 */
#define UDS_RDTC_RDTCEDBR  			0x16   /* rep.DTCExtDataRec.ByRec.Num.	 */
#define UDS_RDTC_RUDMDTCBSM  		0x17   /* rep.UDM.DTCByStatusMask	     */
#define UDS_RDTC_RUDMDTCSSBDTC		0x18   /* rep.UDM.DTCSnap.Rec.ByDTCNum.  */
#define UDS_RDTC_RUDMDTCEDRBDN		0x19   /* rep.UDM.DTCExtDt.Rec.ByDTCNum. */
#define UDS_RDTC_RDTCEDI  			0x1A   /* rep.SupportedDTCExtDataRec.	 */
#define UDS_RDTC_RWWHOBDDTCBMR 		0x42   /* rep.WWHOBDDTCByMaskRecord		 */
#define UDS_RDTC_RWWHOBDDTCWPS 		0x55   /* rep.WWHOBDDTCWithPerm.Status	 */
#define UDS_RDTC_RDTCBRGI  			0x56   /* rep.DTCInfoByDTCRdness.Gr.Id.  */

/******************************************************************************
* Enumerations, structures & Variables
******************************************************************************/

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	iso14229_1_OK = 0x00,
	iso14229_1_YES = 0x40,
	iso14229_1_NO = 0x80,
}iso14229_1_status;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	A_INACTIVE 	 = 0x00,
	A_ACTIVE 	 = 0x01,
	A_LOCKED 	 = 0x80,
	A_NOT_EXISTS = 0xF0
}session_status;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	SA_INACTIVE 	= 0x00,
	SA_IN_PROGRESS	= 0x01,
	SA_ACTIVE 		= 0x02,
	SA_NOT_EXISTS   = 0xF0
}security_access_status;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	RTN_INACTIVE 	= 0x10,
	RTN_ACTIVE 		= 0x20,
	RTN_LOCKED 		= 0x40,
	RTN_NOT_EXISTS  = 0x00
}routine_status;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	RDBID_AS_MEMORY_ADDRESS = 0x02,
	RDBID_AS_RETVAL_OF_FUNC = 0x08
}uds_read_data_by_id_type;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	WRBID_AS_MEMORY_ADDRESS = 0x02,
	WRBID_AS_RETVAL_OF_FUNC = 0x08
}uds_write_data_by_id_type;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	RD_INACTIVE 	= 0x10,
	RD_ACTIVE 		= 0x20,
	RD_NOT_EXISTS   = 0x00
}request_download_status;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	TD_INACTIVE 	= 0x10,
	TD_ACTIVE 		= 0x20,
	TD_LOCKED 		= 0x40,
	TD_NOT_EXISTS   = 0x00
}tranfer_data_status;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	RTN_START 	 = 0x01,
	RTN_STOP 	 = 0x02,
	RTN_RESULT 	 = 0x03,
	RTN_CONTINUE = 0x10
}routine_command;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef enum
{
	VAR_TYPE_u8 = 0x11,
	VAR_TYPE_i8 = 0x12,
	VAR_TYPE_u16 = 0x21,
	VAR_TYPE_i16 = 0x22,
	VAR_TYPE_u32 = 0x41,
	VAR_TYPE_i32 = 0x42,
	VAR_TYPE_arr = 0x19,
}variable_type;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint32_t last_update;
	uint16_t time_limit;
	uint16_t max_response;
}timing_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint8_t sid;
	iso14229_1_status is_supported;
}iso14299_1_sid_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	void (*cb_HR)();
	void (*cb_KOFFONR)();
	void (*cb_SR)();
	void (*cb_ERPSD)();
	void (*cb_DRPSD)();
}uds_ecu_reset_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint16_t id;
	uds_read_data_by_id_type type;
	uint8_t fnr_enabled;
	union
	{
		struct __attribute__((packed))
		{
			void* address;
			uint8_t size;
			uint8_t as_msb;
		}as_addr;
		struct __attribute__((packed))
		{
			void (*func)(uint8_t*,uint8_t*,uint32_t arg);
			uint32_t func_arg;
		}as_func;
	}data;
	uint32_t session;
	uint32_t security_level;
}uds_read_data_by_id_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint16_t id;
	uds_write_data_by_id_type type;
	uint8_t fnr_enabled;
	union
	{
		struct __attribute__((packed))
		{
			void* address;
			void* size;
			variable_type type;
		}as_addr;
		struct __attribute__((packed))
		{
			int (*func)(uint8_t*,uint8_t,uint32_t arg);
			uint32_t func_arg;
			uint32_t size;
		}as_func;
	}data;
	uint32_t session;
	uint32_t security_level;
}uds_write_data_by_id_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint32_t session;
	uint32_t security_level;
	routine_status sts;
	routine_status default_sts;
	uint32_t id;
	uint32_t rst_sz;
	uint8_t (*rountine)(void*, routine_command cmd, uint8_t* data,uint16_t sz);
	uint8_t *rst;
	uint8_t fnr_enabled;
}uds_routine_local_id_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint32_t security_level;
	request_download_status default_sts;
	request_download_status sts;
	uint32_t memory_address;
	uint32_t memory_sz;
}uds_request_download_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint32_t security_level;
	tranfer_data_status default_sts;
	tranfer_data_status sts;
	uint32_t block_counter;
	uint32_t current_address;
	uint32_t remaining_data_len;
	uint32_t expected_data_len;
	uint16_t calculated_crc;
}uds_tranfer_data_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint8_t access_lvl;
	security_access_status sts;
	security_access_status default_sts;
	uint32_t current_seed;
	uint32_t (*key_validation)(uint32_t);
}uds_security_access_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (8)))
{
	uint8_t n_pr;
	uint8_t n_sa;
	uint8_t p_msg;
	uint8_t s_msg;
	uint8_t errn;
	uint32_t last_updated;
	iso15765_t nl;
}iso14229_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

typedef struct __attribute__ ((aligned (4)))
{
	uint8_t id;
	session_status default_sts;
	session_status sts;
	timing_t timeout;
	void (*on_opening)();
	void (*on_unlocking)();
	void (*on_closing)();
}uds_session_t;

/* --- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (ref: xxxxxxxxxx p.xx) ------------ */

extern __attribute__ ((aligned (4)))
					iso14229_t uds_server;
extern __attribute__ ((aligned (4)))
					iso15765_t isotp_handler;
extern __attribute__ ((aligned (4)))
					uds_routine_local_id_t uds_routines[ISO14229_1_NUMOF_ROUTINESBYLOCALID];
extern __attribute__ ((aligned (4)))
					uds_read_data_by_id_t uds_read_data_by_id[ISO14229_1_NUMOF_READDATABYID];
extern __attribute__ ((aligned (4)))
					uds_write_data_by_id_t uds_write_data_by_id[ISO14229_1_NUMOF_WRITEDATABYID];
extern __attribute__ ((aligned (4)))
					uds_tranfer_data_t uds_tranfer_data;
extern __attribute__ ((aligned (4)))
					uds_request_download_t uds_download_request;
extern __attribute__ ((aligned (4)))
					uds_security_access_t uds_security_accesses[ISO14229_1_NUMOF_SECURITYACCESSES];
extern __attribute__ ((aligned (4)))
					uds_ecu_reset_t uds_ecu_reset;
extern __attribute__ ((aligned (4)))
					uds_session_t uds_sessions[ISO14229_1_NUMOF_DIAGSESSIONS] ;

/******************************************************************************
* Declaration | SHIM Functions (implementation @ lib_iso14229_shim.c)
******************************************************************************/

/*
 * SHIM: Get system time. This function should be implemented by
 * the user. 
 */
uint32_t iso14229_getms();

/*
 * SHIM: This function should be implemented by
 * the user to perform post actions.
 */
void iso14229_postinit();

/*
 * SHIM: This function should be implemented by
 * the user to attach the canbus driver.
 */
uint8_t send_frame(cbus_id_type id_type, uint32_t id, cbus_fr_format fr_fmt, uint8_t dlc, uint8_t* dt);

/******************************************************************************
* Declaration | Public (lib-level) Functions
******************************************************************************/

/*
 * Functions related to service: Routine Control
 */
void iso14229_1_srvc_routine_control();
routine_status iso14229_1_srvc_routines_process();

/*
 * Functions related to service: Read memory by address
 */
void iso14229_1_srvc_read_memory_by_address();

/*
 * Functions related to service: Security access
 */
void iso14229_1_srvc_security_access();

/*
 * Functions related to service: Tester Present
 */
void iso14229_1_srvc_tester_present();

/*
 * Functions related to service: Transfer Data
 */
void iso14229_1_srvc_tranfer_data();

/*
 * Functions related to service: Transfer Exit
 */
void iso14229_1_srvc_request_transfer_exit();

/*
 * Functions related to service: Download Request
 */
void iso14229_1_uds_srvc_request_download();

/*
 * Functions related to service: Read Data by LocalID
 */
void iso14229_srvc_read_data_by_localid();

/*
 * Functions related to service: Write Data by LocalID
 */
void iso14229_srvc_write_data_by_localid();

/*
 * Functions related to service: ECU Reset
 */
void iso14229_1_uds_srvc_ecu_reset();

/*
 * Functions related to service: Diagnostic Sessions
 */
void iso14229_1_srvc_diagnostic_session_control();
void iso14229_1_srvc_diagnostic_session_refresh_timeout();

/*
 * Check if a give service is actually supported
 */
iso14229_1_status sid_supported(uint8_t sid);

/*
 * Send Positive Service Response
 */
void iso14229_send(n_ai_t *ai, uint8_t* data, uint16_t sz);

/*
 * Send Negative Service Response
 */
void iso14229_send_NRC(n_ai_t *ai,uint8_t sid, uint8_t code);

/*
 * Service timeout controller
 */
void iso14229_1_srvc_timeouts();

/******************************************************************************
* Declaration | Public Functions
******************************************************************************/

/*
 * Use this function to initialize the library (once)
 */
void iso14229_init();

/*
 * Repetively call this function to process any incoming requests or 
 * pending actions
 */
uint8_t iso14229_process();

/*
 * Check if a process is ongoing
 */
uint8_t iso14229_inactive();

/******************************************************************************
* EOF - NO CODE AFTER THIS LINE
******************************************************************************/
#endif
