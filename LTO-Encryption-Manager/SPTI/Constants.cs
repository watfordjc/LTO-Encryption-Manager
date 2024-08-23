namespace uk.JohnCook.dotnet.LTOEncryptionManager.SPTI
{
	public static class Constants
	{
		internal static readonly Windows.Win32.Foundation.BOOL FALSE = (Windows.Win32.Foundation.BOOL)0;
		internal static readonly Windows.Win32.Foundation.BOOL TRUE = (Windows.Win32.Foundation.BOOL)1;

#pragma warning disable CA1707 // Identifiers should not contain underscores
		public const int SPT_CDB_LENGTH = 32;
		public const int SPT_SENSE_LENGTH = 32;
		public const int SPTWB_DATA_LENGTH = 65280;

		public const int CDB6GENERIC_LENGTH = 6;
		public const int CDB10GENERIC_LENGTH = 10;
		public const int CDB12GENERIC_LENGTH = 12;
		public const int CDB16GENERIC_LENGTH = 16;

		public const int STOR_ADDRESS_TYPE_UNKNOWN = 0x0000;
		public const int STOR_ADDRESS_TYPE_BTL8 = 0x0001;
		public const int STOR_ADDRESS_TYPE_MAX = 0xFFFF;
		public const int STOR_ADDR_BTL8_ADDRESS_LENGTH = 4;

		public const int SCSI_IOCTL_DATA_OUT = 0;
		public const int SCSI_IOCTL_DATA_IN = 1;
		public const int SCSI_IOCTL_DATA_UNSPECIFIED = 2;

		//
		// SCSI bus status codes.
		//

		public const int SCSISTAT_GOOD = 0x00;
		public const int SCSISTAT_CHECK_CONDITION = 0x02;
		public const int SCSISTAT_CONDITION_MET = 0x04;
		public const int SCSISTAT_BUSY = 0x08;
		public const int SCSISTAT_INTERMEDIATE = 0x10;
		public const int SCSISTAT_INTERMEDIATE_COND_MET = 0x14;
		public const int SCSISTAT_RESERVATION_CONFLICT = 0x18;
		public const int SCSISTAT_COMMAND_TERMINATED = 0x22;
		public const int SCSISTAT_QUEUE_FULL = 0x28;

		//
		// SCSI CDB operation codes
		//

		// 6-byte commands:
		public const int SCSIOP_TEST_UNIT_READY = 0x00;
		public const int SCSIOP_REZERO_UNIT = 0x01;
		public const int SCSIOP_REWIND = 0x01;
		public const int SCSIOP_REQUEST_BLOCK_ADDR = 0x02;
		public const int SCSIOP_REQUEST_SENSE = 0x03;
		public const int SCSIOP_FORMAT_UNIT = 0x04;
		public const int SCSIOP_READ_BLOCK_LIMITS = 0x05;
		public const int SCSIOP_REASSIGN_BLOCKS = 0x07;
		public const int SCSIOP_INIT_ELEMENT_STATUS = 0x07;
		public const int SCSIOP_READ6 = 0x08;
		public const int SCSIOP_RECEIVE = 0x08;
		public const int SCSIOP_WRITE6 = 0x0A;
		public const int SCSIOP_PRINT = 0x0A;
		public const int SCSIOP_SEND = 0x0A;
		public const int SCSIOP_SEEK6 = 0x0B;
		public const int SCSIOP_TRACK_SELECT = 0x0B;
		public const int SCSIOP_SLEW_PRINT = 0x0B;
		public const int SCSIOP_SET_CAPACITY = 0x0B;// tape
		public const int SCSIOP_SEEK_BLOCK = 0x0C;
		public const int SCSIOP_PARTITION = 0x0D;
		public const int SCSIOP_READ_REVERSE = 0x0F;
		public const int SCSIOP_WRITE_FILEMARKS = 0x10;
		public const int SCSIOP_FLUSH_BUFFER = 0x10;
		public const int SCSIOP_SPACE = 0x11;
		public const int SCSIOP_INQUIRY = 0x12;
		public const int SCSIOP_VERIFY6 = 0x13;
		public const int SCSIOP_RECOVER_BUF_DATA = 0x14;
		public const int SCSIOP_MODE_SELECT = 0x15;
		public const int SCSIOP_RESERVE_UNIT = 0x16;
		public const int SCSIOP_RELEASE_UNIT = 0x17;
		public const int SCSIOP_COPY = 0x18;
		public const int SCSIOP_ERASE = 0x19;
		public const int SCSIOP_MODE_SENSE = 0x1A;
		public const int SCSIOP_START_STOP_UNIT = 0x1B;
		public const int SCSIOP_STOP_PRINT = 0x1B;
		public const int SCSIOP_LOAD_UNLOAD = 0x1B;
		public const int SCSIOP_RECEIVE_DIAGNOSTIC = 0x1C;
		public const int SCSIOP_SEND_DIAGNOSTIC = 0x1D;
		public const int SCSIOP_MEDIUM_REMOVAL = 0x1E;

		// 10-byte commands
		public const int SCSIOP_READ_FORMATTED_CAPACITY = 0x23;
		public const int SCSIOP_READ_CAPACITY = 0x25;
		public const int SCSIOP_READ = 0x28;
		public const int SCSIOP_WRITE = 0x2A;
		public const int SCSIOP_SEEK = 0x2B;
		public const int SCSIOP_LOCATE = 0x2B;
		public const int SCSIOP_POSITION_TO_ELEMENT = 0x2B;
		public const int SCSIOP_WRITE_VERIFY = 0x2E;
		public const int SCSIOP_VERIFY = 0x2F;
		public const int SCSIOP_SEARCH_DATA_HIGH = 0x30;
		public const int SCSIOP_SEARCH_DATA_EQUAL = 0x31;
		public const int SCSIOP_SEARCH_DATA_LOW = 0x32;
		public const int SCSIOP_SET_LIMITS = 0x33;
		public const int SCSIOP_READ_POSITION = 0x34;
		public const int SCSIOP_SYNCHRONIZE_CACHE = 0x35;
		public const int SCSIOP_COMPARE = 0x39;
		public const int SCSIOP_COPY_COMPARE = 0x3A;
		public const int SCSIOP_WRITE_DATA_BUFF = 0x3B;
		public const int SCSIOP_READ_DATA_BUFF = 0x3C;
		public const int SCSIOP_WRITE_LONG = 0x3F;
		public const int SCSIOP_CHANGE_DEFINITION = 0x40;
		public const int SCSIOP_WRITE_SAME = 0x41;
		public const int SCSIOP_READ_SUB_CHANNEL = 0x42;
		public const int SCSIOP_UNMAP = 0x42;// block device
		public const int SCSIOP_READ_TOC = 0x43;
		public const int SCSIOP_READ_HEADER = 0x44;
		public const int SCSIOP_REPORT_DENSITY_SUPPORT = 0x44;// tape
		public const int SCSIOP_PLAY_AUDIO = 0x45;
		public const int SCSIOP_GET_CONFIGURATION = 0x46;
		public const int SCSIOP_PLAY_AUDIO_MSF = 0x47;
		public const int SCSIOP_PLAY_TRACK_INDEX = 0x48;
		public const int SCSIOP_SANITIZE = 0x48;// block device
		public const int SCSIOP_PLAY_TRACK_RELATIVE = 0x49;
		public const int SCSIOP_GET_EVENT_STATUS = 0x4A;
		public const int SCSIOP_PAUSE_RESUME = 0x4B;
		public const int SCSIOP_LOG_SELECT = 0x4C;
		public const int SCSIOP_LOG_SENSE = 0x4D;
		public const int SCSIOP_STOP_PLAY_SCAN = 0x4E;
		public const int SCSIOP_XDWRITE = 0x50;
		public const int SCSIOP_XPWRITE = 0x51;
		public const int SCSIOP_READ_DISK_INFORMATION = 0x51;
		public const int SCSIOP_READ_DISC_INFORMATION = 0x51;// proper use of disc over disk
		public const int SCSIOP_READ_TRACK_INFORMATION = 0x52;
		public const int SCSIOP_XDWRITE_READ = 0x53;
		public const int SCSIOP_RESERVE_TRACK_RZONE = 0x53;
		public const int SCSIOP_SEND_OPC_INFORMATION = 0x54;// optimum power calibration
		public const int SCSIOP_MODE_SELECT10 = 0x55;
		public const int SCSIOP_RESERVE_UNIT10 = 0x56;
		public const int SCSIOP_RESERVE_ELEMENT = 0x56;
		public const int SCSIOP_RELEASE_UNIT10 = 0x57;
		public const int SCSIOP_RELEASE_ELEMENT = 0x57;
		public const int SCSIOP_REPAIR_TRACK = 0x58;
		public const int SCSIOP_MODE_SENSE10 = 0x5A;
		public const int SCSIOP_CLOSE_TRACK_SESSION = 0x5B;
		public const int SCSIOP_READ_BUFFER_CAPACITY = 0x5C;
		public const int SCSIOP_SEND_CUE_SHEET = 0x5D;
		public const int SCSIOP_PERSISTENT_RESERVE_IN = 0x5E;
		public const int SCSIOP_PERSISTENT_RESERVE_OUT = 0x5F;

		// 12-byte commands
		public const int SCSIOP_REPORT_LUNS = 0xA0;
		public const int SCSIOP_BLANK = 0xA1;
		public const int SCSIOP_ATA_PASSTHROUGH12 = 0xA1;
		public const int SCSIOP_SEND_EVENT = 0xA2;
		public const int SCSIOP_SECURITY_PROTOCOL_IN = 0xA2;
		public const int SCSIOP_SEND_KEY = 0xA3;
		public const int SCSIOP_MAINTENANCE_IN = 0xA3;
		public const int SCSIOP_REPORT_KEY = 0xA4;
		public const int SCSIOP_MAINTENANCE_OUT = 0xA4;
		public const int SCSIOP_MOVE_MEDIUM = 0xA5;
		public const int SCSIOP_LOAD_UNLOAD_SLOT = 0xA6;
		public const int SCSIOP_EXCHANGE_MEDIUM = 0xA6;
		public const int SCSIOP_SET_READ_AHEAD = 0xA7;
		public const int SCSIOP_MOVE_MEDIUM_ATTACHED = 0xA7;
		public const int SCSIOP_READ12 = 0xA8;
		public const int SCSIOP_GET_MESSAGE = 0xA8;
		public const int SCSIOP_SERVICE_ACTION_OUT12 = 0xA9;
		public const int SCSIOP_WRITE12 = 0xAA;
		public const int SCSIOP_SEND_MESSAGE = 0xAB;
		public const int SCSIOP_SERVICE_ACTION_IN12 = 0xAB;
		public const int SCSIOP_GET_PERFORMANCE = 0xAC;
		public const int SCSIOP_READ_DVD_STRUCTURE = 0xAD;
		public const int SCSIOP_WRITE_VERIFY12 = 0xAE;
		public const int SCSIOP_VERIFY12 = 0xAF;
		public const int SCSIOP_SEARCH_DATA_HIGH12 = 0xB0;
		public const int SCSIOP_SEARCH_DATA_EQUAL12 = 0xB1;
		public const int SCSIOP_SEARCH_DATA_LOW12 = 0xB2;
		public const int SCSIOP_SET_LIMITS12 = 0xB3;
		public const int SCSIOP_READ_ELEMENT_STATUS_ATTACHED = 0xB4;
		public const int SCSIOP_REQUEST_VOL_ELEMENT = 0xB5;
		public const int SCSIOP_SECURITY_PROTOCOL_OUT = 0xB5;
		public const int SCSIOP_SEND_VOLUME_TAG = 0xB6;
		public const int SCSIOP_SET_STREAMING = 0xB6;// C/DVD
		public const int SCSIOP_READ_DEFECT_DATA = 0xB7;
		public const int SCSIOP_READ_ELEMENT_STATUS = 0xB8;
		public const int SCSIOP_READ_CD_MSF = 0xB9;
		public const int SCSIOP_SCAN_CD = 0xBA;
		public const int SCSIOP_REDUNDANCY_GROUP_IN = 0xBA;
		public const int SCSIOP_SET_CD_SPEED = 0xBB;
		public const int SCSIOP_REDUNDANCY_GROUP_OUT = 0xBB;
		public const int SCSIOP_PLAY_CD = 0xBC;
		public const int SCSIOP_SPARE_IN = 0xBC;
		public const int SCSIOP_MECHANISM_STATUS = 0xBD;
		public const int SCSIOP_SPARE_OUT = 0xBD;
		public const int SCSIOP_READ_CD = 0xBE;
		public const int SCSIOP_VOLUME_SET_IN = 0xBE;
		public const int SCSIOP_SEND_DVD_STRUCTURE = 0xBF;
		public const int SCSIOP_VOLUME_SET_OUT = 0xBF;
		public const int SCSIOP_INIT_ELEMENT_RANGE = 0xE7;

		// 16-byte commands
		public const int SCSIOP_XDWRITE_EXTENDED16 = 0x80; // disk
		public const int SCSIOP_WRITE_FILEMARKS16 = 0x80; // tape
		public const int SCSIOP_REBUILD16 = 0x81; // disk
		public const int SCSIOP_READ_REVERSE16 = 0x81; // tape
		public const int SCSIOP_REGENERATE16 = 0x82; // disk
		public const int SCSIOP_EXTENDED_COPY = 0x83;
		public const int SCSIOP_POPULATE_TOKEN = 0x83; // disk
		public const int SCSIOP_WRITE_USING_TOKEN = 0x83; // disk
		public const int SCSIOP_RECEIVE_COPY_RESULTS = 0x84;
		public const int SCSIOP_RECEIVE_ROD_TOKEN_INFORMATION = 0x84; //disk
		public const int SCSIOP_ATA_PASSTHROUGH16 = 0x85;
		public const int SCSIOP_ACCESS_CONTROL_IN = 0x86;
		public const int SCSIOP_ACCESS_CONTROL_OUT = 0x87;
		public const int SCSIOP_READ16 = 0x88;
		public const int SCSIOP_COMPARE_AND_WRITE = 0x89;
		public const int SCSIOP_WRITE16 = 0x8A;
		public const int SCSIOP_READ_ATTRIBUTES = 0x8C;
		public const int SCSIOP_WRITE_ATTRIBUTES = 0x8D;
		public const int SCSIOP_WRITE_VERIFY16 = 0x8E;
		public const int SCSIOP_VERIFY16 = 0x8F;
		public const int SCSIOP_PREFETCH16 = 0x90;
		public const int SCSIOP_SYNCHRONIZE_CACHE16 = 0x91;
		public const int SCSIOP_SPACE16 = 0x91; // tape
		public const int SCSIOP_LOCK_UNLOCK_CACHE16 = 0x92;
		public const int SCSIOP_LOCATE16 = 0x92; // tape
		public const int SCSIOP_WRITE_SAME16 = 0x93;
		public const int SCSIOP_ERASE16 = 0x93; // tape
		public const int SCSIOP_ZBC_OUT = 0x94; // Close Zone, Finish Zone, Open Zone, Reset Write Pointer, etc.
		public const int SCSIOP_ZBC_IN = 0x95; // Report Zones, etc.
		public const int SCSIOP_READ_DATA_BUFF16 = 0x9B;
		public const int SCSIOP_READ_CAPACITY16 = 0x9E;
		public const int SCSIOP_GET_LBA_STATUS = 0x9E;
		public const int SCSIOP_GET_PHYSICAL_ELEMENT_STATUS = 0x9E;
		public const int SCSIOP_REMOVE_ELEMENT_AND_TRUNCATE = 0x9E;
		public const int SCSIOP_SERVICE_ACTION_IN16 = 0x9E;
		public const int SCSIOP_SERVICE_ACTION_OUT16 = 0x9F;

		// 32-byte commands
		public const int SCSIOP_OPERATION32 = 0x7F;

		// Enable Vital Product Data Flag (EVPD) used with INQUIRY command.
		public const int CDB_INQUIRY_EVPD = 0x01;

		//
		// Supported Vital Product Data Pages Page (page code 0x00)
		// Contains a list of the vital product data page cods supported by the target
		// or logical unit.
		//

		public const int VPD_MAX_BUFFER_SIZE = 0xff;
		public const int VPD_SUPPORTED_PAGES = 0x00;
		public const int VPD_SERIAL_NUMBER = 0x80;
		public const int VPD_DEVICE_IDENTIFIERS = 0x83;
		public const int VPD_MEDIA_SERIAL_NUMBER = 0x84;
		public const int VPD_SOFTWARE_INTERFACE_IDENTIFIERS = 0x84;
		public const int VPD_NETWORK_MANAGEMENT_ADDRESSES = 0x85;
		public const int VPD_EXTENDED_INQUIRY_DATA = 0x86;
		public const int VPD_MODE_PAGE_POLICY = 0x87;
		public const int VPD_SCSI_PORTS = 0x88;
		public const int VPD_ATA_INFORMATION = 0x89;
		public const int VPD_THIRD_PARTY_COPY = 0x8F;
		public const int VPD_BLOCK_LIMITS = 0xB0;
		public const int VPD_BLOCK_DEVICE_CHARACTERISTICS = 0xB1;
		public const int VPD_LOGICAL_BLOCK_PROVISIONING = 0xB2;
		public const int VPD_ZONED_BLOCK_DEVICE_CHARACTERISTICS = 0xB6;

		/* SPIN / SPOUT Extensions to scsi.h */
		public const int SECURITY_PROTOCOL_INFO = 0x00;
		public const int SECURITY_PROTOCOL_TCG1 = 0x01;
		public const int SECURITY_PROTOCOL_TCG2 = 0x02;
		public const int SECURITY_PROTOCOL_TCG3 = 0x03;
		public const int SECURITY_PROTOCOL_TCG4 = 0x04;
		public const int SECURITY_PROTOCOL_TCG5 = 0x05;
		public const int SECURITY_PROTOCOL_TCG6 = 0x06;
		public const int SECURITY_PROTOCOL_CBCS = 0x07;
		public const int SECURITY_PROTOCOL_TAPE = 0x20;
		public const int SECURITY_PROTOCOL_ADC3 = 0x21;
		public const int SECURITY_PROCOCOL_SA_CREATION_CAPABILITIES = 0x40;
		public const int SECURITY_PROCOCOL_IKEV2_SCSI = 0x41;
		public const int SECURITY_PROCOCOL_UFS = 0xEC;
		public const int SECURITY_PROCOCOL_SD_TRUSTEDFLASH = 0xED;
		public const int SECURITY_PROCOCOL_ATA_PASSWORD = 0xEF;

		public const int SPIN_PROTOCOL_LIST = 0x00;
		public const int SPIN_CERTIFICATE_DATA = 0x01;
		public const int SPIN_SECURITY_COMPLIANCE = 0x02;

		public const int SPIN_SECURITY_COMPLIANCE_FIPS140 = 0x0001;

		public const int SPIN_SECURITY_COMPLIANCE_FIPS140_2 = 0x32;
		public const int SPIN_SECURITY_COMPLIANCE_FIPS140_3 = 0x33;

		public const int SPIN_TAPE_ENCRYPTION_IN_SUPPORT = 0x00;
		public const int SPIN_TAPE_ENCRYPTION_OUT_SUPPORT = 0x01;
		public const int SPIN_TAPE_ENCRYPTION_CAPABILITIES = 0x10;
		public const int SPIN_TAPE_SUPPORTED_KEY_FORMATS = 0x11;
		public const int SPIN_TAPE_ENCRYPTION_MANAGEMENT_CAPABILITIES = 0x12;
		public const int SPIN_TAPE_ENCRYPTION_STATUS = 0x20;
		public const int SPIN_TAPE_NEXT_BLOCK_ENCRYPTION_STATUS = 0x21;
		public const int SPIN_TAPE_WRAPPED_PUBKEY = 0x31;

		public const int SPIN_TAPE_ALGORITHM_AESGCM = 0x00010014;
		public const int SPIN_TAPE_KEY_FORMAT_PLAIN = 0x00;
		public const int SPIN_TAPE_KEY_FORMAT_WRAPPED = 0x02;

		public const int SPIN_TAPE_PUBKEY_TYPE_RSA2048 = 0x00000000;
		public const int SPIN_TAPE_PUBKEY_TYPE_ECC521 = 0x00000010;

		public const int SPIN_TAPE_PUBKEY_FORMAT_RSA2048 = 0x00000000;
		public const int SPIN_TAPE_PUBKEY_FORMAT_ECC521 = 0x00000000;

		public const int SPIN_TAPE_PUBKEY_LENGTH_AES256 = 64;
		public const int SPIN_TAPE_PUBKEY_LENGTH_RSA2048 = 512;
		public const int SPIN_TAPE_PUBKEY_LENGTH_ECC521 = 133;

		public const int SPOUT_TAPE_SET_DATA_ENCRYPTION = 0x0010;

		public const int SPOUT_TAPE_KAD_FORMAT_UNSPEC = 0x00;
		public const int SPOUT_TAPE_KAD_FORMAT_BINARY = 0x01;
		public const int SPOUT_TAPE_KAD_FORMAT_ASCII = 0x02;

		public const int SPOUT_TAPE_KAD_PLAIN_TYPE_UNAUTH = 0x0;
		public const int SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH = 0x1;
		public const int SPOUT_TAPE_KAD_PLAIN_TYPE_NONCE = 0x2;
		public const int SPOUT_TAPE_KAD_PLAIN_TYPE_METADATA = 0x3;

		public const int WRAPPED_KEY_DESCRIPTOR_TYPE_DEVICE_ID = 0x00;
		public const int WRAPPED_KEY_DESCRIPTOR_TYPE_WRAPPER_ID = 0x01;
		public const int WRAPPED_KEY_DESCRIPTOR_TYPE_KEY_INFO = 0x02;
		public const int WRAPPED_KEY_DESCRIPTOR_TYPE_KEY_ID = 0x03;
		public const int WRAPPED_KEY_DESCRIPTOR_TYPE_KEY_LENGTH = 0x04;

		/* Read Attribute Extensions to scsi.h */
		public const int READ_ATTRIBUTE_SERVICE_ATTRIBUTE_VALUES = 0x00;
		public const int READ_ATTRIBUTE_SERVICE_ATTRIBUTE_LIST = 0x01;
		public const int READ_ATTRIBUTE_SERVICE_VOLUME_LIST = 0x02;
		public const int READ_ATTRIBUTE_SERVICE_PARTITION_LIST = 0x03;
		public const int READ_ATTRIBUTE_SERVICE_SUPPORTED_ATTRIBUTES = 0x05;
		/* SCSI_ADSENSE_LUN_NOT_READY(0x04) qualifiers */
		public const int SCSI_SENSEQ_MAM_NOT_ACCESSIBLE = 0x10;
		/* SCSI_ADSENSE_UNRECOVERED_ERROR (0x11) qualifiers */
		public const int SCSI_SENSEQ_MAM_READ_ERROR = 0x12;

		/* Constants for CM/MAM Attributes */
		public const int MAM_REMAINING_PARTITION_CAPACITY = 0x0000;
		public const int MAM_MAXIMUM_PARTITION_CAPACITY = 0x0001;
		public const int MAM_TAPE_ALERT_FLAGS = 0x0002;
		public const int MAM_LOAD_COUNT = 0x0003;
		public const int MAM_REMAINING_MAM_CAPACITY = 0x0004;
		public const int MAM_ASSIGNING_ORG = 0x0005;
		public const int MAM_DENSITY_CODE = 0x0006;
		public const int MAM_INIT_COUNT = 0x0007;
		public const int MAM_VOLUME_ID = 0x0008;
		public const int MAM_VOLUME_CHANGE_REF = 0x0009;
		public const int MAM_SERIAL_ULTIMATE_LOAD = 0x020A;
		public const int MAM_SERIAL_PENULTIMATE_LOAD = 0x020B;
		public const int MAM_SERIAL_ANTEPENULTIMATE_LOAD = 0x020C;
		public const int MAM_SERIAL_PREANTIPENULTIMATE_LOAD = 0x020D;
		public const int MAM_TOTAL_WRITTEN_LIFETIME = 0x0220;
		public const int MAM_TOTAL_READ_LIFETIME = 0x0221;
		public const int MAM_TOTAL_WRITTEN_ULTIMATE_LOAD = 0x0222;
		public const int MAM_TOTAL_READ_ULTIMATE_LOAD = 0x0223;
		public const int MAM_FIRST_ENCRYPTED_BLOCK = 0x0224;
		public const int MAM_FIRST_UNENCRYPTED_BLOCK = 0x0225;
		public const int MAM_MEDIUM_MANUFACTURER = 0x0400;
		public const int MAM_MEDIUM_SERIAL = 0x0401;
		public const int MAM_MEDIUM_LENGTH = 0x0402;
		public const int MAM_MEDIUM_WIDTH = 0x0403;
		public const int MAM_MEDIUM_ASSIGNING_ORG = 0x0404;
		public const int MAM_MEDIUM_DENSITY_CODE = 0x0405;
		public const int MAM_MEDIUM_MANUFACTURE_DATE = 0x0406;
		public const int MAM_MAXIMUM_MAM_CAPACITY = 0x0407;
		public const int MAM_MEDIUM_TYPE = 0x0408;
		public const int MAM_MEDIUM_TYPE_INFO = 0x0409;
		public const int MAM_APP_VENDOR = 0x0800;
		public const int MAM_APP_NAME = 0x0801;
		public const int MAM_APP_VERSION = 0x0802;
		public const int MAM_MEDIUM_USER_LABEL = 0x0803;
		public const int MAM_LAST_WRITE_TIME = 0x0804;
		public const int MAM_TEXT_LOCALE_ID = 0x0805;
		public const int MAM_BARCODE = 0x0806;
		public const int MAM_HOST_SERVER_NAME = 0x0807;
		public const int MAM_MEDIA_POOL = 0x0808;
		public const int MAM_PARTITION_USER_LABEL = 0x0809;
		public const int MAM_LOAD_UNLOAD_AT_PARTITION = 0x080A;
		public const int MAM_APP_FORMAT_VERSION = 0x080B;
		public const int MAM_VOLUME_COHERENCY_INFO = 0x080C;
		public const int MAM_LTFS_MEDIUM_UUID = 0x0820;
		public const int MAM_LTFS_MEDIA_POOL_UUID = 0x0821;
		public const int MAM_HPE_CARTRIDGE_ID = 0x1000;
		public const int MAM_HPE_CARTRIDGE_ID_ALT = 0x1001;
		public const int MAM_HPE_EARLY_WARNING_END_OF_MEDIA = 0x1500;
		public const int MAM_VOLUME_LOCKED = 0x1623;

		public const int MAM_LOCALE_ASCII = 0x00;
		public const int MAM_LOCALE_LATIN_1 = 0x01;
		public const int MAM_LOCALE_LATIN_2 = 0x02;
		public const int MAM_LOCALE_LATIN_3 = 0x03;
		public const int MAM_LOCALE_LATIN_4 = 0x04;
		public const int MAM_LOCALE_LATIN_CYRILLIC = 0x05;
		public const int MAM_LOCALE_LATIN_ARABIC = 0x06;
		public const int MAM_LOCALE_LATIN_GREEK = 0x07;
		public const int MAM_LOCALE_LATIN_HEBREW = 0x08;
		public const int MAM_LOCALE_LATIN_5 = 0x09;
		public const int MAM_LOCALE_LATIN_6 = 0x0A;
		public const int MAM_LOCALE_UNICODE = 0x80;
		public const int MAM_LOCALE_UTF8 = 0x81;

		public const int MAM_FORMAT_BINARY = 0b00;
		public const int MAM_FORMAT_ASCII = 0b01;
		public const int MAM_FORMAT_TEXT = 0b10;
		public const int MAM_FORMAT_RESERVED = 0b11;

		public const int TAPE_ALERT_READ_WARNING = 1;
		public const int TAPE_ALERT_WRITE_WARNING = 2;
		public const int TAPE_ALERT_HARD_ERROR = 3;
		public const int TAPE_ALERT_MEDIA = 4;
		public const int TAPE_ALERT_READ_FAILURE = 5;
		public const int TAPE_ALERT_WRITE_FAILURE = 6;
		public const int TAPE_ALERT_MEDIA_LIFE = 7;
		public const int TAPE_ALERT_NOT_DATA_GRADE = 8;
		public const int TAPE_ALERT_WRITE_PROTECT = 9;
		public const int TAPE_ALERT_NO_REMOVAL = 10;
		public const int TAPE_ALERT_CLEANING_MEDIA = 11;
		public const int TAPE_ALERT_UNSUPPORTED_FORMAT = 12;
		public const int TAPE_ALERT_RECOVERABLE_SNAPPED_TAPE = 13;
		public const int TAPE_ALERT_UNRECOVERABLE_SNAPPED_TAPE = 14;
		public const int TAPE_ALERT_CM_FAILURE = 15;
		public const int TAPE_ALERT_FORCED_EJECT = 16;
		public const int TAPE_ALERT_READ_ONLY_FORMAT = 17;
		public const int TAPE_ALERT_DIR_CORRUPT_ON_LOAD = 18;
		public const int TAPE_ALERT_NEARING_MEDIA_LIFE = 19;
		public const int TAPE_ALERT_CLEAN_NOW = 20;
		public const int TAPE_ALERT_CLEAN_PERIODIC = 21;
		public const int TAPE_ALERT_EXPIRED_CLEANING_MEDIA = 22;
		public const int TAPE_ALERT_INVALID_CLEANING_TAPE = 23;
		public const int TAPE_ALERT_RETENTION_REQUESTED = 24;
		public const int TAPE_ALERT_DUAL_PORT_INTF_ERROR = 25;
		public const int TAPE_ALERT_COOLING_FAN_FAILURE = 26;
		public const int TAPE_ALERT_POWER_SUPPLY = 27;
		public const int TAPE_ALERT_POWER_CONSUMPTION = 28;
		public const int TAPE_ALERT_DRIVE_MAINTENANCE = 29;
		public const int TAPE_ALERT_HARDWARE_A = 30;
		public const int TAPE_ALERT_HARDWARE_B = 31;
		public const int TAPE_ALERT_INTF = 32;
		public const int TAPE_ALERT_EJECT_MEDIA = 33;
		public const int TAPE_ALERT_DL_FAIL = 34;
		public const int TAPE_ALERT_DRIVE_HUMIDITY = 35;
		public const int TAPE_ALERT_DRIVE_TEMP = 36;
		public const int TAPE_ALERT_DRIVE_VOLTAGE = 37;
		public const int TAPE_ALERT_PREDICTIVE_FAILURE = 38;
		public const int TAPE_ALERT_DIAGNOSTICS_REQUIRED = 39;
		public const int TAPE_ALERT_LOADER_HARDWARE_A = 40;
		public const int TAPE_ALERT_LOADER_STRAY_TAPE = 41;
		public const int TAPE_ALERT_LOADER_HARDWARE_B = 42;
		public const int TAPE_ALERT_LOADER_DOOR = 43;
		public const int TAPE_ALERT_LOADER_HARDWARE_C = 44;
		public const int TAPE_ALERT_LOADER_MAGAZINE = 45;
		public const int TAPE_ALERT_LOADER_PREDICTIVE_FAILURE = 46;
		public const int TAPE_ALERT_LOST_STATS = 50;
		public const int TAPE_ALERT_DIR_INVALID_AT_UNLOAD = 51;
		public const int TAPE_ALERT_SYS_AREA_WRITE_FAILURE = 52;
		public const int TAPE_ALERT_SYS_AREA_READ_FAILURE = 53;
		public const int TAPE_ALERT_NO_START_OF_DATA = 54;

		public const int TAPE_ALERT_SEVERITY_INFO = 0;
		public const int TAPE_ALERT_SEVERITY_WARN = 1;
		public const int TAPE_ALERT_SEVERITY_CRIT = 2;
		public const int TAPE_ALERT_SEVERITY_UNKNOWN = 3;
#pragma warning restore CA1707 // Identifiers should not contain underscores
	}
}
