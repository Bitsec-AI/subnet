pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;

library console {

	address constant CONSOLE_ADDRESS = address(0x000000000000000000636F6e736F6c652e6c6f67);



	function _sendLogPayload(bytes memory payload) private view {

		uint256 payloadLength = payload.length;

		address consoleAddress = CONSOLE_ADDRESS;

		assembly {

			let payloadStart := add(payload, 32)

			let r := staticcall(gas(), consoleAddress, payloadStart, payloadLength, 0, 0)

		}

	}



	function log() internal view {

		_sendLogPayload(abi.encodeWithSignature("log()"));

	}



	function logInt(int p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(int)", p0));

	}



	function logUint(uint p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint)", p0));

	}



	function logString(string memory p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string)", p0));

	}



	function logBool(bool p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool)", p0));

	}



	function logAddress(address p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address)", p0));

	}



	function logBytes(bytes memory p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes)", p0));

	}



	function logByte(byte p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(byte)", p0));

	}



	function logBytes1(bytes1 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes1)", p0));

	}



	function logBytes2(bytes2 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes2)", p0));

	}



	function logBytes3(bytes3 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes3)", p0));

	}



	function logBytes4(bytes4 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes4)", p0));

	}



	function logBytes5(bytes5 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes5)", p0));

	}



	function logBytes6(bytes6 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes6)", p0));

	}



	function logBytes7(bytes7 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes7)", p0));

	}



	function logBytes8(bytes8 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes8)", p0));

	}



	function logBytes9(bytes9 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes9)", p0));

	}



	function logBytes10(bytes10 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes10)", p0));

	}



	function logBytes11(bytes11 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes11)", p0));

	}



	function logBytes12(bytes12 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes12)", p0));

	}



	function logBytes13(bytes13 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes13)", p0));

	}



	function logBytes14(bytes14 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes14)", p0));

	}



	function logBytes15(bytes15 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes15)", p0));

	}



	function logBytes16(bytes16 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes16)", p0));

	}



	function logBytes17(bytes17 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes17)", p0));

	}



	function logBytes18(bytes18 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes18)", p0));

	}



	function logBytes19(bytes19 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes19)", p0));

	}



	function logBytes20(bytes20 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes20)", p0));

	}



	function logBytes21(bytes21 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes21)", p0));

	}



	function logBytes22(bytes22 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes22)", p0));

	}



	function logBytes23(bytes23 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes23)", p0));

	}



	function logBytes24(bytes24 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes24)", p0));

	}



	function logBytes25(bytes25 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes25)", p0));

	}



	function logBytes26(bytes26 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes26)", p0));

	}



	function logBytes27(bytes27 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes27)", p0));

	}



	function logBytes28(bytes28 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes28)", p0));

	}



	function logBytes29(bytes29 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes29)", p0));

	}



	function logBytes30(bytes30 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes30)", p0));

	}



	function logBytes31(bytes31 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes31)", p0));

	}



	function logBytes32(bytes32 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes32)", p0));

	}



	function log(uint p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint)", p0));

	}



	function log(string memory p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string)", p0));

	}



	function log(bool p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool)", p0));

	}



	function log(address p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address)", p0));

	}



	function log(uint p0, uint p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint)", p0, p1));

	}



	function log(uint p0, string memory p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string)", p0, p1));

	}



	function log(uint p0, bool p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool)", p0, p1));

	}



	function log(uint p0, address p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address)", p0, p1));

	}



	function log(string memory p0, uint p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint)", p0, p1));

	}



	function log(string memory p0, string memory p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string)", p0, p1));

	}



	function log(string memory p0, bool p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool)", p0, p1));

	}



	function log(string memory p0, address p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address)", p0, p1));

	}



	function log(bool p0, uint p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint)", p0, p1));

	}



	function log(bool p0, string memory p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string)", p0, p1));

	}



	function log(bool p0, bool p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool)", p0, p1));

	}



	function log(bool p0, address p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address)", p0, p1));

	}



	function log(address p0, uint p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint)", p0, p1));

	}



	function log(address p0, string memory p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string)", p0, p1));

	}



	function log(address p0, bool p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool)", p0, p1));

	}



	function log(address p0, address p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address)", p0, p1));

	}



	function log(uint p0, uint p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint)", p0, p1, p2));

	}



	function log(uint p0, uint p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string)", p0, p1, p2));

	}



	function log(uint p0, uint p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool)", p0, p1, p2));

	}



	function log(uint p0, uint p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address)", p0, p1, p2));

	}



	function log(uint p0, string memory p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint)", p0, p1, p2));

	}



	function log(uint p0, string memory p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string)", p0, p1, p2));

	}



	function log(uint p0, string memory p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool)", p0, p1, p2));

	}



	function log(uint p0, string memory p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address)", p0, p1, p2));

	}



	function log(uint p0, bool p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint)", p0, p1, p2));

	}



	function log(uint p0, bool p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string)", p0, p1, p2));

	}



	function log(uint p0, bool p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool)", p0, p1, p2));

	}



	function log(uint p0, bool p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address)", p0, p1, p2));

	}



	function log(uint p0, address p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint)", p0, p1, p2));

	}



	function log(uint p0, address p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string)", p0, p1, p2));

	}



	function log(uint p0, address p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool)", p0, p1, p2));

	}



	function log(uint p0, address p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address)", p0, p1, p2));

	}



	function log(string memory p0, uint p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint)", p0, p1, p2));

	}



	function log(string memory p0, uint p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string)", p0, p1, p2));

	}



	function log(string memory p0, uint p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool)", p0, p1, p2));

	}



	function log(string memory p0, uint p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address)", p0, p1, p2));

	}



	function log(string memory p0, string memory p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint)", p0, p1, p2));

	}



	function log(string memory p0, string memory p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string)", p0, p1, p2));

	}



	function log(string memory p0, string memory p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool)", p0, p1, p2));

	}



	function log(string memory p0, string memory p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address)", p0, p1, p2));

	}



	function log(string memory p0, bool p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint)", p0, p1, p2));

	}



	function log(string memory p0, bool p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string)", p0, p1, p2));

	}



	function log(string memory p0, bool p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool)", p0, p1, p2));

	}



	function log(string memory p0, bool p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address)", p0, p1, p2));

	}



	function log(string memory p0, address p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint)", p0, p1, p2));

	}



	function log(string memory p0, address p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string)", p0, p1, p2));

	}



	function log(string memory p0, address p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool)", p0, p1, p2));

	}



	function log(string memory p0, address p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address)", p0, p1, p2));

	}



	function log(bool p0, uint p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint)", p0, p1, p2));

	}



	function log(bool p0, uint p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string)", p0, p1, p2));

	}



	function log(bool p0, uint p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool)", p0, p1, p2));

	}



	function log(bool p0, uint p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address)", p0, p1, p2));

	}



	function log(bool p0, string memory p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint)", p0, p1, p2));

	}



	function log(bool p0, string memory p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string)", p0, p1, p2));

	}



	function log(bool p0, string memory p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool)", p0, p1, p2));

	}



	function log(bool p0, string memory p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address)", p0, p1, p2));

	}



	function log(bool p0, bool p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint)", p0, p1, p2));

	}



	function log(bool p0, bool p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string)", p0, p1, p2));

	}



	function log(bool p0, bool p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool)", p0, p1, p2));

	}



	function log(bool p0, bool p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address)", p0, p1, p2));

	}



	function log(bool p0, address p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint)", p0, p1, p2));

	}



	function log(bool p0, address p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string)", p0, p1, p2));

	}



	function log(bool p0, address p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool)", p0, p1, p2));

	}



	function log(bool p0, address p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address)", p0, p1, p2));

	}



	function log(address p0, uint p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint)", p0, p1, p2));

	}



	function log(address p0, uint p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string)", p0, p1, p2));

	}



	function log(address p0, uint p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool)", p0, p1, p2));

	}



	function log(address p0, uint p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address)", p0, p1, p2));

	}



	function log(address p0, string memory p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint)", p0, p1, p2));

	}



	function log(address p0, string memory p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string)", p0, p1, p2));

	}



	function log(address p0, string memory p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool)", p0, p1, p2));

	}



	function log(address p0, string memory p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address)", p0, p1, p2));

	}



	function log(address p0, bool p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint)", p0, p1, p2));

	}



	function log(address p0, bool p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string)", p0, p1, p2));

	}



	function log(address p0, bool p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool)", p0, p1, p2));

	}



	function log(address p0, bool p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address)", p0, p1, p2));

	}



	function log(address p0, address p1, uint p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint)", p0, p1, p2));

	}



	function log(address p0, address p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string)", p0, p1, p2));

	}



	function log(address p0, address p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool)", p0, p1, p2));

	}



	function log(address p0, address p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address)", p0, p1, p2));

	}



	function log(uint p0, uint p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint,string)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint,address)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string,string)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string,address)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool,string)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool,address)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address,string)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, uint p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address,address)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint,string)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint,address)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string,string)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string,address)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool,string)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool,address)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address,string)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, string memory p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address,address)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint,string)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint,address)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string,string)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string,address)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool,string)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool,address)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address,string)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, bool p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address,address)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint,string)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint,address)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string,string)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string,address)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool,string)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool,address)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address,uint)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address,string)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address,bool)", p0, p1, p2, p3));

	}



	function log(uint p0, address p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,uint)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,address)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint,string)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint,address)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string,string)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string,address)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool,string)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool,address)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address,string)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, uint p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address,address)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint,string)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint,address)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,string)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,address)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,string)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,address)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,string)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,address)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint,string)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint,address)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,string)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,address)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,string)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,address)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,string)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,address)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint,string)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint,address)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,string)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,address)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,string)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,address)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,uint)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,string)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,address)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint,uint)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint,string)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint,bool)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint,address)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string,uint)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string,string)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string,bool)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string,address)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool,uint)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool,string)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool,bool)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool,address)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address,uint)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address,string)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address,bool)", p0, p1, p2, p3));

	}



	function log(address p0, uint p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address,address)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint,uint)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint,string)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint,bool)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint,address)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,uint)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,string)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,bool)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,address)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,uint)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,string)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,bool)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,address)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,uint)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,string)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,bool)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,address)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint,uint)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint,string)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint,bool)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint,address)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,uint)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,string)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,bool)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,address)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,uint)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,string)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,bool)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,address)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,uint)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,string)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,bool)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,address)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, uint p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint,uint)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, uint p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint,string)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, uint p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint,bool)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, uint p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint,address)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, string memory p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,uint)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,string)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,bool)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,address)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, bool p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,uint)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,string)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,bool)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,address)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, address p2, uint p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,uint)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,string)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,bool)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,address)", p0, p1, p2, p3));

	}



}

abstract contract Context {

    function _msgSender() internal view virtual returns (address payable) {

        return msg.sender;

    }



    function _msgData() internal view virtual returns (bytes memory) {

        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691

        return msg.data;

    }

}

interface IERC165 {

    /**

     * @dev Returns true if this contract implements the interface defined by

     * `interfaceId`. See the corresponding

     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]

     * to learn more about how these ids are created.

     *

     * This function call must use less than 30 000 gas.

     */

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

}

library SafeMath {

    /**

     * @dev Returns the addition of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `+` operator.

     *

     * Requirements:

     *

     * - Addition cannot overflow.

     */

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;

        require(c >= a, "SafeMath: addition overflow");



        return c;

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting on

     * overflow (when the result is negative).

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return sub(a, b, "SafeMath: subtraction overflow");

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on

     * overflow (when the result is negative).

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b <= a, errorMessage);

        uint256 c = a - b;



        return c;

    }



    /**

     * @dev Returns the multiplication of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `*` operator.

     *

     * Requirements:

     *

     * - Multiplication cannot overflow.

     */

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the

        // benefit is lost if 'b' is also tested.

        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522

        if (a == 0) {

            return 0;

        }



        uint256 c = a * b;

        require(c / a == b, "SafeMath: multiplication overflow");



        return c;

    }



    /**

     * @dev Returns the integer division of two unsigned integers. Reverts on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator. Note: this function uses a

     * `revert` opcode (which leaves remaining gas untouched) while Solidity

     * uses an invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return div(a, b, "SafeMath: division by zero");

    }



    /**

     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator. Note: this function uses a

     * `revert` opcode (which leaves remaining gas untouched) while Solidity

     * uses an invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b > 0, errorMessage);

        uint256 c = a / b;

        // assert(a == b * c + a % b); // There is no case in which this doesn't hold



        return c;

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * Reverts when dividing by zero.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        return mod(a, b, "SafeMath: modulo by zero");

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * Reverts with custom message when dividing by zero.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b != 0, errorMessage);

        return a % b;

    }

}

interface IERC20 {

    /**

     * @dev Returns the amount of tokens in existence.

     */

    function totalSupply() external view returns (uint256);



    /**

     * @dev Returns the amount of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);



    /**

     * @dev Moves `amount` tokens from the caller's account to `recipient`.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transfer(address recipient, uint256 amount) external returns (bool);



    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender) external view returns (uint256);



    /**

     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * IMPORTANT: Beware that changing an allowance with this method brings the risk

     * that someone may use both the old and the new allowance by unfortunate

     * transaction ordering. One possible solution to mitigate this race

     * condition is to first reduce the spender's allowance to 0 and set the

     * desired value afterwards:

     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729

     *

     * Emits an {Approval} event.

     */

    function approve(address spender, uint256 amount) external returns (bool);



    /**

     * @dev Moves `amount` tokens from `sender` to `recipient` using the

     * allowance mechanism. `amount` is then deducted from the caller's

     * allowance.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);



    /**

     * @dev Emitted when `value` tokens are moved from one account (`from`) to

     * another (`to`).

     *

     * Note that `value` may be zero.

     */

    event Transfer(address indexed from, address indexed to, uint256 value);



    /**

     * @dev Emitted when the allowance of a `spender` for an `owner` is set by

     * a call to {approve}. `value` is the new allowance.

     */

    event Approval(address indexed owner, address indexed spender, uint256 value);

}

library SafeERC20 {

    using SafeMath for uint256;

    using Address for address;



    function safeTransfer(IERC20 token, address to, uint256 value) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));

    }



    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));

    }



    /**

     * @dev Deprecated. This function has issues similar to the ones found in

     * {IERC20-approve}, and its usage is discouraged.

     *

     * Whenever possible, use {safeIncreaseAllowance} and

     * {safeDecreaseAllowance} instead.

     */

    function safeApprove(IERC20 token, address spender, uint256 value) internal {

        // safeApprove should only be called when setting an initial allowance,

        // or when resetting it to zero. To increase and decrease it, use

        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'

        // solhint-disable-next-line max-line-length

        require((value == 0) || (token.allowance(address(this), spender) == 0),

            "SafeERC20: approve from non-zero to non-zero allowance"

        );

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));

    }



    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).add(value);

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

    }



    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

    }



    /**

     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement

     * on the return value: the return value is optional (but if data is returned, it must not be false).

     * @param token The token targeted by the call.

     * @param data The call data (encoded using abi.encode or one of its variants).

     */

    function _callOptionalReturn(IERC20 token, bytes memory data) private {

        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since

        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that

        // the target address contains contract code and also asserts for success in the low-level call.



        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional

            // solhint-disable-next-line max-line-length

            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");

        }

    }

}

interface IERC721Receiver {

    /**

     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}

     * by `operator` from `from`, this function is called.

     *

     * It must return its Solidity selector to confirm the token transfer.

     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.

     *

     * The selector can be obtained in Solidity with `IERC721.onERC721Received.selector`.

     */

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)

    external returns (bytes4);

}

library Address {

    /**

     * @dev Returns true if `account` is a contract.

     *

     * [IMPORTANT]

     * ====

     * It is unsafe to assume that an address for which this function returns

     * false is an externally-owned account (EOA) and not a contract.

     *

     * Among others, `isContract` will return false for the following

     * types of addresses:

     *

     *  - an externally-owned account

     *  - a contract in construction

     *  - an address where a contract will be created

     *  - an address where a contract lived, but was destroyed

     * ====

     */

    function isContract(address account) internal view returns (bool) {

        // This method relies in extcodesize, which returns 0 for contracts in

        // construction, since the code is only stored at the end of the

        // constructor execution.



        uint256 size;

        // solhint-disable-next-line no-inline-assembly

        assembly { size := extcodesize(account) }

        return size > 0;

    }



    /**

     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to

     * `recipient`, forwarding all available gas and reverting on errors.

     *

     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost

     * of certain opcodes, possibly making contracts go over the 2300 gas limit

     * imposed by `transfer`, making them unable to receive funds via

     * `transfer`. {sendValue} removes this limitation.

     *

     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].

     *

     * IMPORTANT: because control is transferred to `recipient`, care must be

     * taken to not create reentrancy vulnerabilities. Consider using

     * {ReentrancyGuard} or the

     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].

     */

    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");



        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value

        (bool success, ) = recipient.call{ value: amount }("");

        require(success, "Address: unable to send value, recipient may have reverted");

    }



    /**

     * @dev Performs a Solidity function call using a low level `call`. A

     * plain`call` is an unsafe replacement for a function call: use this

     * function instead.

     *

     * If `target` reverts with a revert reason, it is bubbled up by this

     * function (like regular Solidity function calls).

     *

     * Returns the raw returned data. To convert to the expected return value,

     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].

     *

     * Requirements:

     *

     * - `target` must be a contract.

     * - calling `target` with `data` must not revert.

     *

     * _Available since v3.1._

     */

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {

      return functionCall(target, data, "Address: low-level call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with

     * `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {

        return _functionCallWithValue(target, data, 0, errorMessage);

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but also transferring `value` wei to `target`.

     *

     * Requirements:

     *

     * - the calling contract must have an ETH balance of at least `value`.

     * - the called Solidity function must be `payable`.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {

        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");

    }



    /**

     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but

     * with `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {

        require(address(this).balance >= value, "Address: insufficient balance for call");

        return _functionCallWithValue(target, data, value, errorMessage);

    }



    function _functionCallWithValue(address target, bytes memory data, uint256 weiValue, string memory errorMessage) private returns (bytes memory) {

        require(isContract(target), "Address: call to non-contract");



        // solhint-disable-next-line avoid-low-level-calls

        (bool success, bytes memory returndata) = target.call{ value: weiValue }(data);

        if (success) {

            return returndata;

        } else {

            // Look for revert reason and bubble it up if present

            if (returndata.length > 0) {

                // The easiest way to bubble the revert reason is using memory via assembly



                // solhint-disable-next-line no-inline-assembly

                assembly {

                    let returndata_size := mload(returndata)

                    revert(add(32, returndata), returndata_size)

                }

            } else {

                revert(errorMessage);

            }

        }

    }

}

contract LavaToken {

    ///@dev EIP-20 token name for this token

    string public constant name = "Lava ThunderEgg Token";



    ///@dev EIP-20 token symbol for this token

    string public constant symbol = "LAVA";



    ///@dev EIP-20 token decimals for this token

    uint8 public constant decimals = 18;



    ///@dev Total number of tokens in circulation

    uint public totalSupply;



    ///@dev Minter address

    address public minter;



    ///@dev Allowance amounts on behalf of others

    mapping (address => mapping (address => uint96)) internal allowances;



    ///@dev Official record of token balances for each account

    mapping (address => uint96) internal balances;



    ///@dev A record of each accounts delegate

    mapping (address => address) public delegates;



    ///@dev A checkpoint for marking number of votes from a given block

    struct Checkpoint {

        uint32 fromBlock;

        uint96 votes;

    }



    ///@dev A record of votes checkpoints for each account, by index

    mapping (address => mapping (uint32 => Checkpoint)) public checkpoints;



    ///@dev The number of checkpoints for each account

    mapping (address => uint32) public numCheckpoints;



    ///@dev The EIP-712 typehash for the contract's domain

    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");



    ///@dev The EIP-712 typehash for the delegation struct used by the contract

    bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");



    ///@dev A record of states for signing / validating signatures

    mapping (address => uint) public nonces;



    ///@dev An event thats emitted when an account changes its delegate

    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);



    ///@dev An event thats emitted when a delegate account's vote balance changes

    event DelegateVotesChanged(address indexed delegate, uint previousBalance, uint newBalance);



    ///@dev The standard EIP-20 transfer event

    event Transfer(address indexed from, address indexed to, uint256 amount);



    ///@dev The standard EIP-20 approval event

    event Approval(address indexed owner, address indexed spender, uint256 amount);



    ///@dev An event thats emitted when the minter is changed

    event NewMinter(address minter);



    modifier onlyMinter {

        require(msg.sender == minter, "Token:onlyMinter: should only be called by minter");

        _;

    }



    /**

     *@dev Construct a new Fuel token

     * @param initialSupply The initial supply minted at deployment

     * @param account The initial account to grant all the tokens

     */

    constructor(uint initialSupply, address account, address _minter) public {

        totalSupply = safe96(initialSupply, "Token::constructor:amount exceeds 96 bits");

        balances[account] = uint96(initialSupply);

        minter = _minter;

        emit Transfer(address(0), account, initialSupply);

    }



    /**

     *@dev Get the number of tokens `spender` is approved to spend on behalf of `account`

     * @param account The address of the account holding the funds

     * @param spender The address of the account spending the funds

     * @return The number of tokens approved

     */

    function allowance(address account, address spender) external view returns (uint) {

        return allowances[account][spender];

    }



    /**

     *@dev Approve `spender` to transfer up to `amount` from `src`

     * @dev This will overwrite the approval amount for `spender`

     *  and is subject to issues noted [here](https://eips.ethereum.org/EIPS/eip-20#approve)

     * @param spender The address of the account which may transfer tokens

     * @param rawAmount The number of tokens that are approved (2^256-1 means infinite)

     * @return Whether or not the approval succeeded

     */

    function approve(address spender, uint rawAmount) external returns (bool) {

        uint96 amount;

        if (rawAmount == uint(-1)) {

            amount = uint96(-1);

        } else {

            amount = safe96(rawAmount, "Token::approve: amount exceeds 96 bits");

        }



        allowances[msg.sender][spender] = amount;



        emit Approval(msg.sender, spender, amount);

        return true;

    }



    /**

     *@dev Get the number of tokens held by the `account`

     * @param account The address of the account to get the balance of

     * @return The number of tokens held

     */

    function balanceOf(address account) external view returns (uint) {

        return balances[account];

    }



    /**

     *@dev Mint `amount` tokens to `dst`

     * @param dst The address of the destination account

     * @param rawAmount The number of tokens to mint

     *@dev only callable by minter

     */

    function mint(address dst, uint rawAmount) external onlyMinter {

        uint96 amount = safe96(rawAmount, "Token::mint: amount exceeds 96 bits");

        _mintTokens(dst, amount);

    }



    /**

     *@dev Burn `amount` tokens

     * @param rawAmount The number of tokens to burn

     */

    function burn(uint rawAmount) external {

        uint96 amount = safe96(rawAmount, "Token::burn: amount exceeds 96 bits");

        _burnTokens(msg.sender, amount);

    }



    /**

     *@dev Change minter address to `account`

     * @param account The address of the new minter

     *@dev only callable by minter

     */

    function changeMinter(address account) external onlyMinter {

        minter = account;

        emit NewMinter(account);

    }



    /**

     *@dev Transfer `amount` tokens from `msg.sender` to `dst`

     * @param dst The address of the destination account

     * @param rawAmount The number of tokens to transfer

     * @return Whether or not the transfer succeeded

     */

    function transfer(address dst, uint rawAmount) external returns (bool) {

        uint96 amount = safe96(rawAmount, "Token::transfer: amount exceeds 96 bits");

        _transferTokens(msg.sender, dst, amount);

        return true;

    }



    /**

     *@dev Transfer `amount` tokens from `src` to `dst`

     * @param src The address of the source account

     * @param dst The address of the destination account

     * @param rawAmount The number of tokens to transfer

     * @return Whether or not the transfer succeeded

     */

    function transferFrom(address src, address dst, uint rawAmount) external returns (bool) {

        address spender = msg.sender;

        uint96 spenderAllowance = allowances[src][spender];

        uint96 amount = safe96(rawAmount, "Token::approve: amount exceeds 96 bits");



        if (spender != src && spenderAllowance != uint96(-1)) {

            uint96 newAllowance = sub96(spenderAllowance, amount, "Token::transferFrom: transfer amount exceeds spender allowance");

            allowances[src][spender] = newAllowance;



            emit Approval(src, spender, newAllowance);

        }



        _transferTokens(src, dst, amount);

        return true;

    }



    /**

     *@dev Delegate votes from `msg.sender` to `delegatee`

     * @param delegatee The address to delegate votes to

     */

    function delegate(address delegatee) public {

        return _delegate(msg.sender, delegatee);

    }



    /**

     *@dev Delegates votes from signatory to `delegatee`

     * @param delegatee The address to delegate votes to

     * @param nonce The contract state required to match the signature

     * @param expiry The time at which to expire the signature

     * @param v The recovery byte of the signature

     * @param r Half of the ECDSA signature pair

     * @param s Half of the ECDSA signature pair

     */

    function delegateBySig(address delegatee, uint nonce, uint expiry, uint8 v, bytes32 r, bytes32 s) public {

        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), getChainId(), address(this)));

        bytes32 structHash = keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        address signatory = ecrecover(digest, v, r, s);

        require(signatory != address(0), "Token::delegateBySig: invalid signature");

        require(nonce == nonces[signatory]++, "Token::delegateBySig: invalid nonce");

        require(now <= expiry, "Token::delegateBySig: signature expired");

        return _delegate(signatory, delegatee);

    }



    /**

     *@dev Gets the current votes balance for `account`

     * @param account The address to get votes balance

     * @return The number of current votes for `account`

     */

    function getCurrentVotes(address account) external view returns (uint96) {

        uint32 nCheckpoints = numCheckpoints[account];

        return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;

    }



    /**

     *@dev Determine the prior number of votes for an account as of a block number

     * @dev Block number must be a finalized block or else this function will revert to prevent misinformation.

     * @param account The address of the account to check

     * @param blockNumber The block number to get the vote balance at

     * @return The number of votes the account had as of the given block

     */

    function getPriorVotes(address account, uint blockNumber) public view returns (uint96) {

        require(blockNumber < block.number, "Token::getPriorVotes: not yet determined");



        uint32 nCheckpoints = numCheckpoints[account];

        if (nCheckpoints == 0) {

            return 0;

        }



        // First check most recent balance

        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {

            return checkpoints[account][nCheckpoints - 1].votes;

        }



        // Next check implicit zero balance

        if (checkpoints[account][0].fromBlock > blockNumber) {

            return 0;

        }



        uint32 lower = 0;

        uint32 upper = nCheckpoints - 1;

        while (upper > lower) {

            uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow

            Checkpoint memory cp = checkpoints[account][center];

            if (cp.fromBlock == blockNumber) {

                return cp.votes;

            } else if (cp.fromBlock < blockNumber) {

                lower = center;

            } else {

                upper = center - 1;

            }

        }

        return checkpoints[account][lower].votes;

    }



    function _delegate(address delegator, address delegatee) internal {

        address currentDelegate = delegates[delegator];

        uint96 delegatorBalance = balances[delegator];

        delegates[delegator] = delegatee;



        emit DelegateChanged(delegator, currentDelegate, delegatee);



        _moveDelegates(currentDelegate, delegatee, delegatorBalance);

    }



    function _transferTokens(address src, address dst, uint96 amount) internal {

        require(src != address(0), "Token::_transferTokens: cannot transfer from the zero address");

        require(dst != address(0), "Token::_transferTokens: cannot transfer to the zero address");



        balances[src] = sub96(balances[src], amount, "Token::_transferTokens: transfer amount exceeds balance");

        balances[dst] = add96(balances[dst], amount, "Token::_transferTokens: transfer amount overflows");

        emit Transfer(src, dst, amount);



        _moveDelegates(delegates[src], delegates[dst], amount);

    }



    function _mintTokens(address dst, uint96 amount) internal {

        require(dst != address(0), "Token::_mintTokens: cannot transfer to the zero address");

        uint96 supply = safe96(totalSupply, "Token::_mintTokens: totalSupply exceeds 96 bits");

        totalSupply = add96(supply, amount, "Token::_mintTokens: totalSupply exceeds 96 bits");

        balances[dst] = add96(balances[dst], amount, "Token::_mintTokens: transfer amount overflows");

        emit Transfer(address(0), dst, amount);



        _moveDelegates(address(0), delegates[dst], amount);

    }



    function _burnTokens(address src, uint96 amount) internal {

        uint96 supply = safe96(totalSupply, "Token::_burnTokens: totalSupply exceeds 96 bits");

        totalSupply = sub96(supply, amount, "Token::_burnTokens:totalSupply underflow");

        balances[src] = sub96(balances[src], amount, "Token::_burnTokens: amount overflows");

        emit Transfer(src, address(0), amount);



        _moveDelegates(delegates[src], address(0), amount);

    }



    function _moveDelegates(address srcRep, address dstRep, uint96 amount) internal {

        if (srcRep != dstRep && amount > 0) {

            if (srcRep != address(0)) {

                uint32 srcRepNum = numCheckpoints[srcRep];

                uint96 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;

                uint96 srcRepNew = sub96(srcRepOld, amount, "Token::_moveVotes: vote amount underflows");

                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);

            }



            if (dstRep != address(0)) {

                uint32 dstRepNum = numCheckpoints[dstRep];

                uint96 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;

                uint96 dstRepNew = add96(dstRepOld, amount, "Token::_moveVotes: vote amount overflows");

                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);

            }

        }

    }



    function _writeCheckpoint(address delegatee, uint32 nCheckpoints, uint96 oldVotes, uint96 newVotes) internal {

        uint32 blockNumber = safe32(block.number, "Token::_writeCheckpoint: block number exceeds 32 bits");



        if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {

            checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;

        } else {

            checkpoints[delegatee][nCheckpoints] = Checkpoint(blockNumber, newVotes);

            numCheckpoints[delegatee] = nCheckpoints + 1;

        }



        emit DelegateVotesChanged(delegatee, oldVotes, newVotes);

    }



    function safe32(uint n, string memory errorMessage) internal pure returns (uint32) {

        require(n < 2**32, errorMessage);

        return uint32(n);

    }



    function safe96(uint n, string memory errorMessage) internal pure returns (uint96) {

        require(n < 2**96, errorMessage);

        return uint96(n);

    }



    function add96(uint96 a, uint96 b, string memory errorMessage) internal pure returns (uint96) {

        uint96 c = a + b;

        require(c >= a, errorMessage);

        return c;

    }



    function sub96(uint96 a, uint96 b, string memory errorMessage) internal pure returns (uint96) {

        require(b <= a, errorMessage);

        return a - b;

    }



    function getChainId() internal pure returns (uint) {

        uint256 chainId;

        assembly { chainId := chainid() }

        return chainId;

    }

}

interface IERC721Receiver {



    /// @notice Handle the receipt of an NFT

    /// @dev The ERC721 smart contract calls this function on the recipient

    ///  after a `transfer`. This function MAY throw to revert and reject the

    ///  transfer. Return of other than the magic value MUST result in the

    ///  transaction being reverted.

    ///  Note: the contract address is always the message sender.

    /// @param _operator The address which called `safeTransferFrom` function

    /// @param _from The address which previously owned the token

    /// @param _tokenId The NFT identifier which is being transferred

    /// @param _data Additional data with no specified format

    /// @return `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`

    ///  unless throwing

    function onERC721Received(

        address _operator,

        address _from,

        uint256 _tokenId,

        bytes calldata _data

    )

    external

    returns (bytes4);

}

interface IERC721Token {



    /// @dev This emits when ownership of any NFT changes by any mechanism.

    ///      This event emits when NFTs are created (`from` == 0) and destroyed

    ///      (`to` == 0). Exception: during contract creation, any number of NFTs

    ///      may be created and assigned without emitting Transfer. At the time of

    ///      any transfer, the approved address for that NFT (if any) is reset to none.

    event Transfer(

        address indexed from,

        address indexed to,

        uint256 indexed tokenId

    );



    /// @dev This emits when the approved address for an NFT is changed or

    ///      reaffirmed. The zero address indicates there is no approved address.

    ///      When a Transfer event emits, this also indicates that the approved

    ///      address for that NFT (if any) is reset to none.

    event Approval(

        address indexed owner,

        address indexed approved,

        uint256 indexed tokenId

    );



    /// @dev This emits when an operator is enabled or disabled for an owner.

    ///      The operator can manage all NFTs of the owner.

    event ApprovalForAll(

        address indexed owner,

        address indexed operator,

        bool approved

    );



    /// @notice Transfers the ownership of an NFT from one address to another address

    /// @dev This works identically to the other function with an extra data parameter,

    ///      except this function just sets data to "".

    /// @param _from The current owner of the NFT

    /// @param _to The new owner

    /// @param _tokenId The NFT to transfer

    function safeTransferFrom(

        address _from,

        address _to,

        uint256 _tokenId

    )

    external;



    /// @notice Transfers the ownership of an NFT from one address to another address

    /// @dev Throws unless `msg.sender` is the current owner, an authorized

    ///      perator, or the approved address for this NFT. Throws if `_from` is

    ///      not the current owner. Throws if `_to` is the zero address. Throws if

    ///      `_tokenId` is not a valid NFT. When transfer is complete, this function

    ///      checks if `_to` is a smart contract (code size > 0). If so, it calls

    ///      `onERC721Received` on `_to` and throws if the return value is not

    ///      `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.

    /// @param _from The current owner of the NFT

    /// @param _to The new owner

    /// @param _tokenId The NFT to transfer

    /// @param _data Additional data with no specified format, sent in call to `_to`

    function safeTransferFrom(

        address _from,

        address _to,

        uint256 _tokenId,

        bytes calldata _data

    )

    external;



    /// @notice Change or reaffirm the approved address for an NFT

    /// @dev The zero address indicates there is no approved address.

    ///      Throws unless `msg.sender` is the current NFT owner, or an authorized

    ///      operator of the current owner.

    /// @param _approved The new approved NFT controller

    /// @param _tokenId The NFT to approve

    function approve(address _approved, uint256 _tokenId)

    external;



    /// @notice Enable or disable approval for a third party ("operator") to manage

    ///         all of `msg.sender`'s assets

    /// @dev Emits the ApprovalForAll event. The contract MUST allow

    ///      multiple operators per owner.

    /// @param _operator Address to add to the set of authorized operators

    /// @param _approved True if the operator is approved, false to revoke approval

    function setApprovalForAll(address _operator, bool _approved)

    external;



    /// @notice Count all NFTs assigned to an owner

    /// @dev NFTs assigned to the zero address are considered invalid, and this

    ///      function throws for queries about the zero address.

    /// @param _owner An address for whom to query the balance

    /// @return The number of NFTs owned by `_owner`, possibly zero

    function balanceOf(address _owner)

    external

    view

    returns (uint256);



    /// @notice Transfer ownership of an NFT -- THE CALLER IS RESPONSIBLE

    ///         TO CONFIRM THAT `_to` IS CAPABLE OF RECEIVING NFTS OR ELSE

    ///         THEY MAY BE PERMANENTLY LOST

    /// @dev Throws unless `msg.sender` is the current owner, an authorized

    ///      operator, or the approved address for this NFT. Throws if `_from` is

    ///      not the current owner. Throws if `_to` is the zero address. Throws if

    ///      `_tokenId` is not a valid NFT.

    /// @param _from The current owner of the NFT

    /// @param _to The new owner

    /// @param _tokenId The NFT to transfer

    function transferFrom(

        address _from,

        address _to,

        uint256 _tokenId

    )

    external;



    /// @notice Find the owner of an NFT

    /// @dev NFTs assigned to zero address are considered invalid, and queries

    ///      about them do throw.

    /// @param _tokenId The identifier for an NFT

    /// @return The address of the owner of the NFT

    function ownerOf(uint256 _tokenId)

    external

    view

    returns (address);



    /// @notice Get the approved address for a single NFT

    /// @dev Throws if `_tokenId` is not a valid NFT.

    /// @param _tokenId The NFT to find the approved address for

    /// @return The approved address for this NFT, or the zero address if there is none

    function getApproved(uint256 _tokenId)

    external

    view

    returns (address);



    /// @notice Query if an address is an authorized operator for another address

    /// @param _owner The address that owns the NFTs

    /// @param _operator The address that acts on behalf of the owner

    /// @return True if `_operator` is an approved operator for `_owner`, false otherwise

    function isApprovedForAll(address _owner, address _operator)

    external

    view

    returns (bool);

}

contract Godable {

    address private _god;



    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    /**

     * @dev Initializes the contract setting the deployer as the initial owner.

     */

    constructor () internal {

        address msgSender = msg.sender;

        _god = msgSender;

        emit OwnershipTransferred(address(0), msgSender);

    }



    /**

     * @dev Returns the address of the current owner.

     */

    function god() public view returns (address) {

        return _god;

    }



    /**

     * @dev Throws if called by any account other than the owner.

     */

    modifier onlyGod() {

        require(_god == msg.sender, "Godable: caller is not the god");

        _;

    }



    /**

     * @dev Transfers ownership of the contract to a new account (`newOwner`).

     * Can only be called by the current owner.

     */

    function transferGod(address newOwner) public virtual onlyGod {

        require(newOwner != address(0), "Godable: new owner is the zero address");

        emit OwnershipTransferred(_god, newOwner);

        _god = newOwner;

    }

}

library Strings {



    // via https://github.com/oraclize/ethereum-api/blob/master/oraclizeAPI_0.5.sol

    function strConcat(string memory _a, string memory _b, string memory _c, string memory _d, string memory _e) internal pure returns (string memory _concatenatedString) {

        bytes memory _ba = bytes(_a);

        bytes memory _bb = bytes(_b);

        bytes memory _bc = bytes(_c);

        bytes memory _bd = bytes(_d);

        bytes memory _be = bytes(_e);

        string memory abcde = new string(_ba.length + _bb.length + _bc.length + _bd.length + _be.length);

        bytes memory babcde = bytes(abcde);

        uint k = 0;

        uint i = 0;

        for (i = 0; i < _ba.length; i++) {

            babcde[k++] = _ba[i];

        }

        for (i = 0; i < _bb.length; i++) {

            babcde[k++] = _bb[i];

        }

        for (i = 0; i < _bc.length; i++) {

            babcde[k++] = _bc[i];

        }

        for (i = 0; i < _bd.length; i++) {

            babcde[k++] = _bd[i];

        }

        for (i = 0; i < _be.length; i++) {

            babcde[k++] = _be[i];

        }

        return string(babcde);

    }



    function strConcat(string memory _a, string memory _b) internal pure returns (string memory) {

        return strConcat(_a, _b, "", "", "");

    }



    function strConcat(string memory _a, string memory _b, string memory _c) internal pure returns (string memory) {

        return strConcat(_a, _b, _c, "", "");

    }



    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {

        if (_i == 0) {

            return "0";

        }

        uint j = _i;

        uint len;

        while (j != 0) {

            len++;

            j /= 10;

        }

        bytes memory bstr = new bytes(len);

        uint k = len - 1;

        while (_i != 0) {

            bstr[k--] = byte(uint8(48 + _i % 10));

            _i /= 10;

        }

        return string(bstr);

    }

}

contract ERC721ReceiverMock is IERC721Receiver {

    bytes4 private _retval;

    bool private _reverts;



    event Received(address operator, address from, uint256 tokenId, bytes data, uint256 gas);



    constructor (bytes4 retval, bool reverts) public {

        _retval = retval;

        _reverts = reverts;

    }



    function onERC721Received(address operator, address from, uint256 tokenId, bytes memory data)

    public override returns (bytes4)

    {

        require(!_reverts, "ERC721ReceiverMock: reverting");

        emit Received(operator, from, tokenId, data, gasleft());

        return _retval;

    }

}

contract ERC165 is IERC165 {

    /*

     * bytes4(keccak256('supportsInterface(bytes4)')) == 0x01ffc9a7

     */

    bytes4 private constant _INTERFACE_ID_ERC165 = 0x01ffc9a7;



    /**

     * @dev Mapping of interface ids to whether or not it's supported.

     */

    mapping(bytes4 => bool) private _supportedInterfaces;



    constructor () internal {

        // Derived contracts need only register support for their own interfaces,

        // we register support for ERC165 itself here

        _registerInterface(_INTERFACE_ID_ERC165);

    }



    /**

     * @dev See {IERC165-supportsInterface}.

     *

     * Time complexity O(1), guaranteed to always use less than 30 000 gas.

     */

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {

        return _supportedInterfaces[interfaceId];

    }



    /**

     * @dev Registers the contract as an implementer of the interface defined by

     * `interfaceId`. Support of the actual ERC165 interface is automatic and

     * registering its interface id is not required.

     *

     * See {IERC165-supportsInterface}.

     *

     * Requirements:

     *

     * - `interfaceId` cannot be the ERC165 invalid interface (`0xffffffff`).

     */

    function _registerInterface(bytes4 interfaceId) internal virtual {

        require(interfaceId != 0xffffffff, "ERC165: invalid interface id");

        _supportedInterfaces[interfaceId] = true;

    }

}

contract ERC20 is Context, IERC20 {

    using SafeMath for uint256;

    using Address for address;



    mapping (address => uint256) private _balances;



    mapping (address => mapping (address => uint256)) private _allowances;



    uint256 private _totalSupply;



    string private _name;

    string private _symbol;

    uint8 private _decimals;



    /**

     * @dev Sets the values for {name} and {symbol}, initializes {decimals} with

     * a default value of 18.

     *

     * To select a different value for {decimals}, use {_setupDecimals}.

     *

     * All three of these values are immutable: they can only be set once during

     * construction.

     */

    constructor (string memory name, string memory symbol) public {

        _name = name;

        _symbol = symbol;

        _decimals = 18;

    }



    /**

     * @dev Returns the name of the token.

     */

    function name() public view returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the symbol of the token, usually a shorter version of the

     * name.

     */

    function symbol() public view returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the number of decimals used to get its user representation.

     * For example, if `decimals` equals `2`, a balance of `505` tokens should

     * be displayed to a user as `5,05` (`505 / 10 ** 2`).

     *

     * Tokens usually opt for a value of 18, imitating the relationship between

     * Ether and Wei. This is the value {ERC20} uses, unless {_setupDecimals} is

     * called.

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view returns (uint8) {

        return _decimals;

    }



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view override returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view override returns (uint256) {

        return _balances[account];

    }



    /**

     * @dev See {IERC20-transfer}.

     *

     * Requirements:

     *

     * - `recipient` cannot be the zero address.

     * - the caller must have a balance of at least `amount`.

     */

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {

        _transfer(_msgSender(), recipient, amount);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view virtual override returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 amount) public virtual override returns (bool) {

        _approve(_msgSender(), spender, amount);

        return true;

    }



    /**

     * @dev See {IERC20-transferFrom}.

     *

     * Emits an {Approval} event indicating the updated allowance. This is not

     * required by the EIP. See the note at the beginning of {ERC20};

     *

     * Requirements:

     * - `sender` and `recipient` cannot be the zero address.

     * - `sender` must have a balance of at least `amount`.

     * - the caller must have allowance for ``sender``'s tokens of at least

     * `amount`.

     */

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {

        _transfer(sender, recipient, amount);

        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));

        return true;

    }



    /**

     * @dev Atomically increases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {

        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));

        return true;

    }



    /**

     * @dev Atomically decreases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     * - `spender` must have allowance for the caller of at least

     * `subtractedValue`.

     */

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {

        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));

        return true;

    }



    /**

     * @dev Moves tokens `amount` from `sender` to `recipient`.

     *

     * This is internal function is equivalent to {transfer}, and can be used to

     * e.g. implement automatic token fees, slashing mechanisms, etc.

     *

     * Emits a {Transfer} event.

     *

     * Requirements:

     *

     * - `sender` cannot be the zero address.

     * - `recipient` cannot be the zero address.

     * - `sender` must have a balance of at least `amount`.

     */

    function _transfer(address sender, address recipient, uint256 amount) internal virtual {

        require(sender != address(0), "ERC20: transfer from the zero address");

        require(recipient != address(0), "ERC20: transfer to the zero address");



        _beforeTokenTransfer(sender, recipient, amount);



        _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance");

        _balances[recipient] = _balances[recipient].add(amount);

        emit Transfer(sender, recipient, amount);

    }



    /** @dev Creates `amount` tokens and assigns them to `account`, increasing

     * the total supply.

     *

     * Emits a {Transfer} event with `from` set to the zero address.

     *

     * Requirements

     *

     * - `to` cannot be the zero address.

     */

    function _mint(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: mint to the zero address");



        _beforeTokenTransfer(address(0), account, amount);



        _totalSupply = _totalSupply.add(amount);

        _balances[account] = _balances[account].add(amount);

        emit Transfer(address(0), account, amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`, reducing the

     * total supply.

     *

     * Emits a {Transfer} event with `to` set to the zero address.

     *

     * Requirements

     *

     * - `account` cannot be the zero address.

     * - `account` must have at least `amount` tokens.

     */

    function _burn(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: burn from the zero address");



        _beforeTokenTransfer(account, address(0), amount);



        _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance");

        _totalSupply = _totalSupply.sub(amount);

        emit Transfer(account, address(0), amount);

    }



    /**

     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.

     *

     * This internal function is equivalent to `approve`, and can be used to

     * e.g. set automatic allowances for certain subsystems, etc.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `owner` cannot be the zero address.

     * - `spender` cannot be the zero address.

     */

    function _approve(address owner, address spender, uint256 amount) internal virtual {

        require(owner != address(0), "ERC20: approve from the zero address");

        require(spender != address(0), "ERC20: approve to the zero address");



        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }



    /**

     * @dev Sets {decimals} to a value other than the default one of 18.

     *

     * WARNING: This function should only be called from the constructor. Most

     * applications that interact with token contracts will not expect

     * {decimals} to ever change, and may work incorrectly if it does.

     */

    function _setupDecimals(uint8 decimals_) internal {

        _decimals = decimals_;

    }



    /**

     * @dev Hook that is called before any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * will be to transferred to `to`.

     * - when `from` is zero, `amount` tokens will be minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }

}

contract ThunderEgg is Godable, IERC721Token, ERC165 {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    // ** Chef



    // Info of each ThunderEgg.

    struct ThunderEggInfo {

        uint256 amount;     // How many LP tokens the user has provided.

        uint256 rewardDebt; // Reward debt. See explanation below.

        //

        // We do some fancy math here. Basically, any point in time, the amount of lava entitled to a user but is pending to be distributed is:

        //

        //   pending reward = (user.amount * pool.accLavaPerShare) - user.rewardDebt

        //

        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:

        //   1. The pool's `accLavaPerShare` (and `lastRewardBlock`) gets updated.

        //   2. User receives the pending reward sent to his/her address.

        //   3. User's `amount` gets updated.

        //   4. User's `rewardDebt` gets updated.

    }



    // Info of each sacred grove.

    struct SacredGrove {

        IERC20 lpToken;           // Address of LP token contract.

        uint256 allocPoint;       // How many allocation points assigned to this pool. lavas to distribute per block.

        uint256 lastRewardBlock;  // Last block number that lavas distribution occurs.

        uint256 accLavaPerShare; // Accumulated lava per share, times 1e18. See below.

        uint256 totalSupply; // max ThunderEggs for this pool

        uint256 endBlock; // god has spoken - this pool is 'ova

    }



    // The lavaToken TOKEN!

    LavaToken public lava;



    // Block number when bonus period ends.

    uint256 public bonusEndBlock;



    // Lava tokens created per block.

    uint256 public lavaPerBlock;



    // Bonus muliplier for early makers.

    uint256 public constant BONUS_MULTIPLIER = 10;



    // Offering to the GODS

    uint256 public godsOffering = 80; // 1.25%



    // Info of each grove.

    SacredGrove[] public sacredGrove;



    // Info of each user that stakes LP tokens.

    mapping(uint256 => mapping(uint256 => ThunderEggInfo)) public thunderEggInfoMapping;



    // Total allocation poitns. Must be the sum of all allocation points in all groves.

    uint256 public totalAllocPoint = 0;



    // The block number when mining starts.

    uint256 public startBlock;



    mapping(address => bool) public isSacredGrove;



    event Deposit(address indexed user, uint256 indexed groveId, uint256 amount);

    event Withdraw(address indexed user, uint256 indexed groveId, uint256 amount);

    event EmergencyWithdraw(address indexed user, uint256 indexed groveId, uint256 amount);



    // ** end Chef



    // ** ERC721



    bytes4 private constant _INTERFACE_ID_ERC721 = 0x80ac58cd;

    bytes4 private constant _INTERFACE_ID_ERC721_METADATA = 0x5b5e139f;



    // Function selector for ERC721Receiver.onERC721Received

    // 0x150b7a02

    bytes4 constant internal ERC721_RECEIVED = bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));



    string public baseTokenURI;



    // Note: the first token ID will be 1

    uint256 public tokenPointer;



    // Token name

    string public name = "ThunderEgg";



    // Token symbol

    string public symbol = "TEGG";



    // total supply across sacred groves

    uint256 public totalSupply;

    uint256 public totalSpawned;

    uint256 public totalDestroyed;



    // Mapping of eggId => owner

    mapping(uint256 => address) internal thunderEggIdToOwner;

    mapping(uint256 => uint256) internal thunderEggIdToBirth;

    mapping(uint256 => bytes32) internal thunderEggIdToName;



    mapping(address => uint256) public ownerToThunderEggId;



    // Mapping of eggId => approved address

    mapping(uint256 => address) internal approvals;



    // Mapping of owner => operator => approved

    mapping(address => mapping(address => bool)) internal operatorApprovals;



    // ** end ERC721



    constructor(

        LavaToken _lava,

        uint256 _lavaPerBlock,

        uint256 _startBlock,

        uint256 _bonusEndBlock

    ) public {

        lava = _lava;

        lavaPerBlock = _lavaPerBlock;

        bonusEndBlock = _bonusEndBlock;

        startBlock = _startBlock;



        _registerInterface(_INTERFACE_ID_ERC721);

        _registerInterface(_INTERFACE_ID_ERC721_METADATA);

    }



    function sacredGroveLength() external view returns (uint256) {

        return sacredGrove.length;

    }



    // Add a new sacred grove. Can only be called by god!!

    function addSacredGrove(uint256 _allocPoint, IERC20 _lpToken, bool _withUpdate) public onlyGod {

        require(!isSacredGrove[address(_lpToken)], "This is already a known sacred grove");



        if (_withUpdate) {

            massUpdateSacredGroves();

        }



        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;

        totalAllocPoint = totalAllocPoint.add(_allocPoint);

        sacredGrove.push(SacredGrove({

            lpToken : _lpToken,

            allocPoint : _allocPoint,

            lastRewardBlock : lastRewardBlock,

            accLavaPerShare : 0,

            totalSupply : 0,

            endBlock : 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

            }));



        isSacredGrove[address(_lpToken)] = true;

    }



    // Update the given grove's allocation point. Can only be called by the owner.

    function set(uint256 _groveId, uint256 _allocPoint, bool _withUpdate) public onlyGod {

        if (_withUpdate) {

            massUpdateSacredGroves();

        }

        totalAllocPoint = totalAllocPoint.sub(sacredGrove[_groveId].allocPoint).add(_allocPoint);

        sacredGrove[_groveId].allocPoint = _allocPoint;

    }



    function end(uint256 _groveId, uint256 _endBlock, bool _withUpdate) public onlyGod {

        SacredGrove storage grove = sacredGrove[_groveId];

        grove.endBlock = _endBlock;



        if (_withUpdate) {

            massUpdateSacredGroves();

        }

    }



    // Return reward multiplier over the given _from to _to block.

    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {

        if (_to <= bonusEndBlock) {

            return _to.sub(_from).mul(BONUS_MULTIPLIER);

        } else if (_from >= bonusEndBlock) {

            return _to.sub(_from);

        } else {

            return bonusEndBlock.sub(_from).mul(BONUS_MULTIPLIER).add(_to.sub(bonusEndBlock));

        }

    }



    function thunderEggStats(uint256 _groveId, uint256 _eggId) external view returns (address _owner, uint256 _birth, uint256 _age, uint256 _lp, uint256 _lava, bytes32 _name) {

        if (!_exists(_eggId)) {

            return (address(0x0), 0, 0, 0, 0, bytes32(0x0));

        }



        ThunderEggInfo storage info = thunderEggInfoMapping[_groveId][_eggId];



        return (

        thunderEggIdToOwner[_eggId],

        thunderEggIdToBirth[_eggId],

        block.number - thunderEggIdToBirth[_eggId],

        info.amount,

        _calculatePendingLava(_groveId, _eggId),

        thunderEggIdToName[_eggId]

        );

    }



    // View function to see pending LAVAs on frontend.

    function pendingLava(uint256 _groveId, uint256 _eggId) external view returns (uint256) {

        // no ThunderEgg, no lava!

        if (!_exists(_eggId)) {

            return 0;

        }



        return _calculatePendingLava(_groveId, _eggId);

    }



    function _calculatePendingLava(uint256 _groveId, uint256 _eggId) internal view returns (uint256) {

        SacredGrove storage grove = sacredGrove[_groveId];

        ThunderEggInfo storage info = thunderEggInfoMapping[_groveId][_eggId];



        uint256 accLavaPerShare = grove.accLavaPerShare;



        uint256 lpSupply = grove.lpToken.balanceOf(address(this));

        if (block.number > grove.lastRewardBlock && lpSupply != 0) {

            uint256 multiplier = getMultiplier(grove.lastRewardBlock, block.number <= grove.endBlock ? block.number : grove.endBlock);

            uint256 lavaReward = multiplier.mul(lavaPerBlock).mul(grove.allocPoint).div(totalAllocPoint);

            accLavaPerShare = accLavaPerShare.add(lavaReward.mul(1e18).div(lpSupply));

        }



        return info.amount.mul(accLavaPerShare).div(1e18).sub(info.rewardDebt);

    }



    // Update reward variables for all grove. Be careful of gas spending!

    function massUpdateSacredGroves() public {

        uint256 length = sacredGrove.length;

        for (uint256 groveId = 0; groveId < length; ++groveId) {

            updateSacredGrove(groveId);

        }

    }



    // Update reward variables of the given grove to be up-to-date.

    function updateSacredGrove(uint256 _groveId) public {

        SacredGrove storage grove = sacredGrove[_groveId];

        if (block.number <= grove.lastRewardBlock) {

            return;

        }



        uint256 lpSupply = grove.lpToken.balanceOf(address(this));

        if (lpSupply == 0) {

            grove.lastRewardBlock = block.number;

            return;

        }



        uint256 multiplier = getMultiplier(grove.lastRewardBlock, block.number <= grove.endBlock ? block.number : grove.endBlock);

        uint256 lavaReward = multiplier.mul(lavaPerBlock).mul(grove.allocPoint).div(totalAllocPoint);



        // offering to the gods

        lava.mint(god(), lavaReward.div(godsOffering));



        // reward for ThunderEggs

        lava.mint(address(this), lavaReward);



        grove.accLavaPerShare = grove.accLavaPerShare.add(lavaReward.mul(1e18).div(lpSupply));

        grove.lastRewardBlock = block.number;

    }



    // mint the ThunderEgg by depositing LP tokens,

    function spawn(uint256 _groveId, uint256 _amount, bytes32 _name) public {

        require(ownerToThunderEggId[msg.sender] == 0, "Thor has already blessed you with a ThunderEgg!");

        require(_amount > 0, "You must sacrifice your LP tokens to the gods!");



        updateSacredGrove(_groveId);



        // Thunder 🥚 time!

        uint256 eggId = _mint(_groveId, msg.sender, _name);



        SacredGrove storage pool = sacredGrove[_groveId];

        ThunderEggInfo storage info = thunderEggInfoMapping[_groveId][eggId];



        // credit the staked amount

        pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);

        info.amount = info.amount.add(_amount);



        info.rewardDebt = info.amount.mul(pool.accLavaPerShare).div(1e18);

        emit Deposit(msg.sender, _groveId, _amount);

    }



    // Destroy and get all the tokens back - bye bye NFT!

    function destroy(uint256 _groveId) public {



        uint256 eggId = ownerToThunderEggId[msg.sender];

        require(eggId != 0, "No ThunderEgg!");



        updateSacredGrove(_groveId);



        SacredGrove storage pool = sacredGrove[_groveId];

        ThunderEggInfo storage info = thunderEggInfoMapping[_groveId][eggId];



        // burn the token - send all rewards and LP back!

        _burn(_groveId, eggId);



        // pay out rewards from the ThunderEgg

        uint256 pending = info.amount.mul(pool.accLavaPerShare).div(1e18).sub(info.rewardDebt);

        if (pending > 0) {

            safeLavaTransfer(msg.sender, pending);

        }



        // send all LP back...

        pool.lpToken.safeTransfer(address(msg.sender), info.amount);



        info.rewardDebt = info.amount.mul(pool.accLavaPerShare).div(1e18);

        emit Withdraw(msg.sender, _groveId, info.amount);

    }



    // Safe sushi transfer function, just in case if rounding error causes pool to not have enough SUSHIs.

    function safeLavaTransfer(address _to, uint256 _amount) internal {

        uint256 lavaBal = lava.balanceOf(address(this));

        if (_amount > lavaBal) {

            lava.transfer(_to, lavaBal);

        } else {

            lava.transfer(_to, _amount);

        }

    }



    // *** ERC721 functions below



    function isContract(address account) internal view returns (bool) {

        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts

        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned

        // for accounts without code, i.e. `keccak256('')`

        bytes32 codehash;

        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

        // solhint-disable-next-line no-inline-assembly

        assembly {codehash := extcodehash(account)}

        return (codehash != accountHash && codehash != 0x0);

    }



    function _checkOnERC721Received(address from, address to, uint256 eggId, bytes memory _data) private returns (bool) {

        if (!isContract(to)) {

            return true;

        }

        // solhint-disable-next-line avoid-low-level-calls

        (bool success, bytes memory returndata) = to.call(abi.encodeWithSelector(

                IERC721Receiver(to).onERC721Received.selector,

                msg.sender,

                from,

                eggId,

                _data

            ));



        if (!success) {

            if (returndata.length > 0) {

                // solhint-disable-next-line no-inline-assembly

                assembly {

                    let returndata_size := mload(returndata)

                    revert(add(32, returndata), returndata_size)

                }

            } else {

                revert("ERC721: transfer to non ERC721Receiver implementer");

            }

        } else {

            bytes4 retval = abi.decode(returndata, (bytes4));

            return (retval == ERC721_RECEIVED);

        }



        return true;

    }



    function setGodsOffering(uint256 _godsOffering) external onlyGod {

        godsOffering = _godsOffering;

    }



    function setBaseTokenURI(string calldata _uri) external onlyGod {

        baseTokenURI = _uri;

    }



    function setName(uint256 _eggId, bytes32 _name) external onlyGod {

        thunderEggIdToName[_eggId] = _name;

    }



    function _mint(uint256 _groveId, address _to, bytes32 _name) internal returns (uint256) {

        require(_to != address(0), "ERC721: mint to the zero address");



        SacredGrove storage grove = sacredGrove[_groveId];

        require(grove.endBlock >= block.number, 'This grove is not longer fertile');



        tokenPointer = tokenPointer.add(1);

        uint256 eggId = tokenPointer;



        // Mint

        thunderEggIdToOwner[eggId] = _to;

        ownerToThunderEggId[msg.sender] = eggId;



        // birth

        thunderEggIdToBirth[eggId] = block.number;



        // name

        thunderEggIdToName[eggId] = _name;



        // MetaData

        grove.totalSupply = grove.totalSupply.add(1);

        totalSupply = totalSupply.add(1);

        totalSpawned = totalSpawned.add(1);



        // Single Transfer event for a single token

        emit Transfer(address(0), _to, eggId);



        return eggId;

    }



    function exists(uint256 _eggId) external view returns (bool) {

        return _exists(_eggId);

    }



    function _exists(uint256 _eggId) internal view returns (bool) {

        return thunderEggIdToOwner[_eggId] != address(0);

    }



    function tokenURI(uint256 _eggId) external view returns (string memory) {

        require(_exists(_eggId), "ERC721Metadata: URI query for nonexistent token");

        return Strings.strConcat(baseTokenURI, Strings.uint2str(_eggId));

    }



    function _burn(uint256 _groveId, uint256 _eggId) internal {

        require(_exists(_eggId), "must exist");



        address owner = thunderEggIdToOwner[_eggId];



        require(owner == msg.sender, "Must own the egg!");



        SacredGrove storage pool = sacredGrove[_groveId];



        thunderEggIdToOwner[_eggId] = address(0);

        ownerToThunderEggId[msg.sender] = 0;



        pool.totalSupply = pool.totalSupply.sub(1);

        totalSupply = totalSupply.sub(1);

        totalDestroyed = totalDestroyed.add(1);



        emit Transfer(

            owner,

            address(0),

            _eggId

        );

    }



    function safeTransferFrom(address _from, address _to, uint256 _eggId) override public {

        safeTransferFrom(_from, _to, _eggId, "");

    }



    function safeTransferFrom(address _from, address _to, uint256 _eggId, bytes memory _data) override public {

        transferFrom(_from, _to, _eggId);

        require(_checkOnERC721Received(_from, _to, _eggId, _data), "ERC721: transfer to non ERC721Receiver implementer");

    }



    function approve(address _approved, uint256 _eggId) override external {

        address owner = ownerOf(_eggId);

        require(_approved != owner, "ERC721: approval to current owner");



        require(

            msg.sender == owner || isApprovedForAll(owner, msg.sender),

            "ERC721: approve caller is not owner nor approved for all"

        );



        approvals[_eggId] = _approved;

        emit Approval(

            owner,

            _approved,

            _eggId

        );

    }



    function setApprovalForAll(address _operator, bool _approved) override external {

        require(_operator != msg.sender, "ERC721: approve to caller");



        operatorApprovals[msg.sender][_operator] = _approved;

        emit ApprovalForAll(

            msg.sender,

            _operator,

            _approved

        );

    }



    function balanceOf(address _owner) override external view returns (uint256) {

        require(_owner != address(0), "ERC721: balance query for the zero address");

        return ownerToThunderEggId[_owner] != 0 ? 1 : 0;

    }



    function transferFrom(address _from, address _to, uint256 _eggId) override public {

        require(

            _to != address(0),

            "ERC721: transfer to the zero address"

        );



        address owner = ownerOf(_eggId);

        require(

            _from == owner,

            "ERC721: transfer of token that is not own"

        );



        address spender = msg.sender;

        address approvedAddress = getApproved(_eggId);

        require(

            spender == owner ||

            isApprovedForAll(owner, spender) ||

            approvedAddress == spender,

            "ERC721: transfer caller is not owner nor approved"

        );



        if (approvedAddress != address(0)) {

            approvals[_eggId] = address(0);

        }



        emit Approval(owner, address(0), _eggId);



        thunderEggIdToOwner[_eggId] = _to;

        ownerToThunderEggId[_from] = 0;

        ownerToThunderEggId[_to] = _eggId;



        emit Transfer(

            _from,

            _to,

            _eggId

        );

    }



    function ownerOf(uint256 _eggId) override public view returns (address) {

        require(_exists(_eggId), "ERC721: operator query for nonexistent token");

        return thunderEggIdToOwner[_eggId];

    }



    function getApproved(uint256 _eggId) override public view returns (address) {

        require(_exists(_eggId), "ERC721: approved query for nonexistent token");

        return approvals[_eggId];

    }



    function isApprovedForAll(address _owner, address _operator) override public view returns (bool) {

        return operatorApprovals[_owner][_operator];

    }

}



contract MockERC20 is ERC20 {

    constructor(

        string memory name,

        string memory symbol,

        uint256 supply

    ) public ERC20(name, symbol) {

        _mint(msg.sender, supply);

    }



    function mint(address _to, uint256 _amount) public {

        _mint(_to, _amount);

    }

}
