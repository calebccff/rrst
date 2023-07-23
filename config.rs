use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum rrst_control_method {
	RRST_CONTROL_NONE,
	RRST_CONTROL_RTS_DTR,
	RRST_CONTROL_QCOM_DBG,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum qcom_dbg_type {
	QCOM_DBG_TYPE_NORMAL,
	QCOM_DBG_TYPE_NOPWR, // For devices like phones that must be reset by holding the power button
}

#[repr(C)]
#[derive(Debug)]
pub struct RRSTConfig {
	name: *const c_char,
	port: *const c_char,
	baud_bootloader: u32,
	baud_linux: u32,
	linux_detect: *const c_char,
	control_method: rrst_control_method,
	control_port: *const c_char,
	qcom_dbg_type: qcom_dbg_type,
}
