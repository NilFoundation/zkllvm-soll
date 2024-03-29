// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// RUN: %soll --lang=Yul %s

// solidity Version 0.8.6
/********************************** Source Code **********************************
pragma solidity =0.8.6;

contract TestBuiltIn {
  constructor() payable {
  }

  function builtin(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external pure {
    ecrecover(digest, v, r, s);
  }
}
**********************************************************************************/

/*=====================================================*
 *                       WARNING                       *
 *  Solidity to Yul compilation is still EXPERIMENTAL  *
 *       It can result in LOSS OF FUNDS or worse       *
 *                !USE AT YOUR OWN RISK!               *
 *=====================================================*/


object "TestBuiltIn_25" {
    code {
        /// @src 0:101,274
        mstore(64, 128)

        constructor_TestBuiltIn_25()

        let _1 := allocate_unbounded()
        codecopy(_1, dataoffset("TestBuiltIn_25_deployed"), datasize("TestBuiltIn_25_deployed"))

        return(_1, datasize("TestBuiltIn_25_deployed"))

        function allocate_unbounded() -> memPtr {
            memPtr := mload(64)
        }

        function constructor_TestBuiltIn_25() {

            /// @src 0:126,153

        }

    }
    object "TestBuiltIn_25_deployed" {
        code {
            /// @src 0:101,274
            mstore(64, 128)

            if iszero(lt(calldatasize(), 4))
            {
                let selector := shift_right_224_unsigned(calldataload(0))
                switch selector

                case 0x78b1e368
                {
                    // builtin(bytes32,uint8,bytes32,bytes32)

                    if callvalue() { revert_error_ca66f745a3ce8ff40e2ccaf1ad45db7774001b90d25810abd9040049be7bf4bb() }
                    let param_0, param_1, param_2, param_3 :=  abi_decode_tuple_t_bytes32t_uint8t_bytes32t_bytes32(4, calldatasize())
                    fun_builtin_24(param_0, param_1, param_2, param_3)
                    let memPos := allocate_unbounded()
                    let memEnd := abi_encode_tuple__to__fromStack(memPos  )
                    return(memPos, sub(memEnd, memPos))
                }

                default {}
            }
            if iszero(calldatasize()) {  }
            revert_error_42b3090547df1d2001c96683413b8cf91c1b902ef5e3cb8d9f6f304cf7446f74()

            function abi_decode_t_bytes32(offset, end) -> value {
                value := calldataload(offset)
                validator_revert_t_bytes32(value)
            }

            function abi_decode_t_uint8(offset, end) -> value {
                value := calldataload(offset)
                validator_revert_t_uint8(value)
            }

            function abi_decode_tuple_t_bytes32t_uint8t_bytes32t_bytes32(headStart, dataEnd) -> value0, value1, value2, value3 {
                if slt(sub(dataEnd, headStart), 128) { revert_error_dbdddcbe895c83990c08b3492a0e83918d802a52331272ac6fdb6a7c4aea3b1b() }

                {

                    let offset := 0

                    value0 := abi_decode_t_bytes32(add(headStart, offset), dataEnd)
                }

                {

                    let offset := 32

                    value1 := abi_decode_t_uint8(add(headStart, offset), dataEnd)
                }

                {

                    let offset := 64

                    value2 := abi_decode_t_bytes32(add(headStart, offset), dataEnd)
                }

                {

                    let offset := 96

                    value3 := abi_decode_t_bytes32(add(headStart, offset), dataEnd)
                }

            }

            function abi_encode_t_bytes32_to_t_bytes32_fromStack(value, pos) {
                mstore(pos, cleanup_t_bytes32(value))
            }

            function abi_encode_t_uint8_to_t_uint8_fromStack(value, pos) {
                mstore(pos, cleanup_t_uint8(value))
            }

            function abi_encode_tuple__to__fromStack(headStart ) -> tail {
                tail := add(headStart, 0)

            }

            function abi_encode_tuple_t_bytes32_t_uint8_t_bytes32_t_bytes32__to_t_bytes32_t_uint8_t_bytes32_t_bytes32__fromStack(headStart , value0, value1, value2, value3) -> tail {
                tail := add(headStart, 128)

                abi_encode_t_bytes32_to_t_bytes32_fromStack(value0,  add(headStart, 0))

                abi_encode_t_uint8_to_t_uint8_fromStack(value1,  add(headStart, 32))

                abi_encode_t_bytes32_to_t_bytes32_fromStack(value2,  add(headStart, 64))

                abi_encode_t_bytes32_to_t_bytes32_fromStack(value3,  add(headStart, 96))

            }

            function allocate_unbounded() -> memPtr {
                memPtr := mload(64)
            }

            function cleanup_t_bytes32(value) -> cleaned {
                cleaned := value
            }

            function cleanup_t_uint8(value) -> cleaned {
                cleaned := and(value, 0xff)
            }

            function fun_builtin_24(var_digest_7, var_v_9, var_r_11, var_s_13) {
                /// @src 0:157,272

                /// @src 0:251,257
                let _1 := var_digest_7
                let expr_17 := _1
                /// @src 0:259,260
                let _2 := var_v_9
                let expr_18 := _2
                /// @src 0:262,263
                let _3 := var_r_11
                let expr_19 := _3
                /// @src 0:265,266
                let _4 := var_s_13
                let expr_20 := _4
                /// @src 0:241,267

                let _5 := allocate_unbounded()
                let _6 := abi_encode_tuple_t_bytes32_t_uint8_t_bytes32_t_bytes32__to_t_bytes32_t_uint8_t_bytes32_t_bytes32__fromStack(_5 , expr_17, expr_18, expr_19, expr_20)

                mstore(0, 0)

                let _7 := staticcall(gas(), 1 , _5, sub(_6, _5), 0, 32)
                if iszero(_7) { revert_forward_1() }
                let expr_21 := shift_left_0(mload(0))

            }

            function revert_error_42b3090547df1d2001c96683413b8cf91c1b902ef5e3cb8d9f6f304cf7446f74() {
                revert(0, 0)
            }

            function revert_error_c1322bf8034eace5e0b5c7295db60986aa89aae5e0ea0873e4689e076861a5db() {
                revert(0, 0)
            }

            function revert_error_ca66f745a3ce8ff40e2ccaf1ad45db7774001b90d25810abd9040049be7bf4bb() {
                revert(0, 0)
            }

            function revert_error_dbdddcbe895c83990c08b3492a0e83918d802a52331272ac6fdb6a7c4aea3b1b() {
                revert(0, 0)
            }

            function revert_forward_1() {
                let pos := allocate_unbounded()
                returndatacopy(pos, 0, returndatasize())
                revert(pos, returndatasize())
            }

            function shift_left_0(value) -> newValue {
                newValue :=

                shl(0, value)

            }

            function shift_right_224_unsigned(value) -> newValue {
                newValue :=

                shr(224, value)

            }

            function validator_revert_t_bytes32(value) {
                if iszero(eq(value, cleanup_t_bytes32(value))) { revert(0, 0) }
            }

            function validator_revert_t_uint8(value) {
                if iszero(eq(value, cleanup_t_uint8(value))) { revert(0, 0) }
            }

        }

        data ".metadata" hex"a2646970667358221220e2d9d8a553c43f36f682caa774190b205e88bb0b638b6d5b2685f2cb40b85fee64736f6c63430008060033"
    }

}

