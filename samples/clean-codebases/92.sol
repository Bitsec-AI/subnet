pragma solidity 0.5.15;

contract CairoVerifierContract {

    function verifyProofExternal(

        uint256[] calldata proofParams, uint256[] calldata proof, uint256[] calldata publicInput)

        external;

}

contract CpuConstraintPoly {

    // The Memory map during the execution of this contract is as follows:

    // [0x0, 0x20) - periodic_column/pedersen/points/x.

    // [0x20, 0x40) - periodic_column/pedersen/points/y.

    // [0x40, 0x60) - periodic_column/ecdsa/generator_points/x.

    // [0x60, 0x80) - periodic_column/ecdsa/generator_points/y.

    // [0x80, 0xa0) - trace_length.

    // [0xa0, 0xc0) - offset_size.

    // [0xc0, 0xe0) - half_offset_size.

    // [0xe0, 0x100) - initial_ap.

    // [0x100, 0x120) - initial_pc.

    // [0x120, 0x140) - final_ap.

    // [0x140, 0x160) - final_pc.

    // [0x160, 0x180) - memory/multi_column_perm/perm/interaction_elm.

    // [0x180, 0x1a0) - memory/multi_column_perm/hash_interaction_elm0.

    // [0x1a0, 0x1c0) - memory/multi_column_perm/perm/public_memory_prod.

    // [0x1c0, 0x1e0) - rc16/perm/interaction_elm.

    // [0x1e0, 0x200) - rc16/perm/public_memory_prod.

    // [0x200, 0x220) - rc_min.

    // [0x220, 0x240) - rc_max.

    // [0x240, 0x260) - pedersen/shift_point.x.

    // [0x260, 0x280) - pedersen/shift_point.y.

    // [0x280, 0x2a0) - initial_pedersen_addr.

    // [0x2a0, 0x2c0) - initial_rc_addr.

    // [0x2c0, 0x2e0) - ecdsa/sig_config.alpha.

    // [0x2e0, 0x300) - ecdsa/sig_config.shift_point.x.

    // [0x300, 0x320) - ecdsa/sig_config.shift_point.y.

    // [0x320, 0x340) - ecdsa/sig_config.beta.

    // [0x340, 0x360) - initial_ecdsa_addr.

    // [0x360, 0x380) - initial_checkpoints_addr.

    // [0x380, 0x3a0) - final_checkpoints_addr.

    // [0x3a0, 0x3c0) - trace_generator.

    // [0x3c0, 0x3e0) - oods_point.

    // [0x3e0, 0x440) - interaction_elements.

    // [0x440, 0x2980) - coefficients.

    // [0x2980, 0x3f20) - oods_values.

    // ----------------------- end of input data - -------------------------

    // [0x3f20, 0x3f40) - composition_degree_bound.

    // [0x3f40, 0x3f60) - intermediate_value/cpu/decode/opcode_rc/bit_0.

    // [0x3f60, 0x3f80) - intermediate_value/cpu/decode/opcode_rc/bit_1.

    // [0x3f80, 0x3fa0) - intermediate_value/cpu/decode/opcode_rc/bit_2.

    // [0x3fa0, 0x3fc0) - intermediate_value/cpu/decode/opcode_rc/bit_4.

    // [0x3fc0, 0x3fe0) - intermediate_value/cpu/decode/opcode_rc/bit_3.

    // [0x3fe0, 0x4000) - intermediate_value/cpu/decode/opcode_rc/bit_9.

    // [0x4000, 0x4020) - intermediate_value/cpu/decode/opcode_rc/bit_5.

    // [0x4020, 0x4040) - intermediate_value/cpu/decode/opcode_rc/bit_6.

    // [0x4040, 0x4060) - intermediate_value/cpu/decode/opcode_rc/bit_7.

    // [0x4060, 0x4080) - intermediate_value/cpu/decode/opcode_rc/bit_8.

    // [0x4080, 0x40a0) - intermediate_value/npc_reg_0.

    // [0x40a0, 0x40c0) - intermediate_value/cpu/decode/opcode_rc/bit_10.

    // [0x40c0, 0x40e0) - intermediate_value/cpu/decode/opcode_rc/bit_11.

    // [0x40e0, 0x4100) - intermediate_value/cpu/decode/opcode_rc/bit_12.

    // [0x4100, 0x4120) - intermediate_value/cpu/decode/opcode_rc/bit_13.

    // [0x4120, 0x4140) - intermediate_value/cpu/decode/opcode_rc/bit_14.

    // [0x4140, 0x4160) - intermediate_value/memory/address_diff_0.

    // [0x4160, 0x4180) - intermediate_value/rc16/diff_0.

    // [0x4180, 0x41a0) - intermediate_value/pedersen/hash0/ec_subset_sum/bit_0.

    // [0x41a0, 0x41c0) - intermediate_value/pedersen/hash0/ec_subset_sum/bit_neg_0.

    // [0x41c0, 0x41e0) - intermediate_value/pedersen/hash1/ec_subset_sum/bit_0.

    // [0x41e0, 0x4200) - intermediate_value/pedersen/hash1/ec_subset_sum/bit_neg_0.

    // [0x4200, 0x4220) - intermediate_value/pedersen/hash2/ec_subset_sum/bit_0.

    // [0x4220, 0x4240) - intermediate_value/pedersen/hash2/ec_subset_sum/bit_neg_0.

    // [0x4240, 0x4260) - intermediate_value/pedersen/hash3/ec_subset_sum/bit_0.

    // [0x4260, 0x4280) - intermediate_value/pedersen/hash3/ec_subset_sum/bit_neg_0.

    // [0x4280, 0x42a0) - intermediate_value/rc_builtin/value0_0.

    // [0x42a0, 0x42c0) - intermediate_value/rc_builtin/value1_0.

    // [0x42c0, 0x42e0) - intermediate_value/rc_builtin/value2_0.

    // [0x42e0, 0x4300) - intermediate_value/rc_builtin/value3_0.

    // [0x4300, 0x4320) - intermediate_value/rc_builtin/value4_0.

    // [0x4320, 0x4340) - intermediate_value/rc_builtin/value5_0.

    // [0x4340, 0x4360) - intermediate_value/rc_builtin/value6_0.

    // [0x4360, 0x4380) - intermediate_value/rc_builtin/value7_0.

    // [0x4380, 0x43a0) - intermediate_value/ecdsa/signature0/doubling_key/x_squared.

    // [0x43a0, 0x43c0) - intermediate_value/ecdsa/signature0/exponentiate_generator/bit_0.

    // [0x43c0, 0x43e0) - intermediate_value/ecdsa/signature0/exponentiate_generator/bit_neg_0.

    // [0x43e0, 0x4400) - intermediate_value/ecdsa/signature0/exponentiate_key/bit_0.

    // [0x4400, 0x4420) - intermediate_value/ecdsa/signature0/exponentiate_key/bit_neg_0.

    // [0x4420, 0x46e0) - expmods.

    // [0x46e0, 0x49c0) - denominator_invs.

    // [0x49c0, 0x4ca0) - denominators.

    // [0x4ca0, 0x4e00) - numerators.

    // [0x4e00, 0x50e0) - adjustments.

    // [0x50e0, 0x51a0) - expmod_context.



    function() external {

        uint256 res;

        assembly {

            let PRIME := 0x800000000000011000000000000000000000000000000000000000000000001

            // Copy input from calldata to memory.

            calldatacopy(0x0, 0x0, /*Input data size*/ 0x3f20)

            let point := /*oods_point*/ mload(0x3c0)

            // Initialize composition_degree_bound to 2 * trace_length.

            mstore(0x3f20, mul(2, /*trace_length*/ mload(0x80)))

            function expmod(base, exponent, modulus) -> res {

              let p := /*expmod_context*/ 0x50e0

              mstore(p, 0x20)                 // Length of Base.

              mstore(add(p, 0x20), 0x20)      // Length of Exponent.

              mstore(add(p, 0x40), 0x20)      // Length of Modulus.

              mstore(add(p, 0x60), base)      // Base.

              mstore(add(p, 0x80), exponent)  // Exponent.

              mstore(add(p, 0xa0), modulus)   // Modulus.

              // Call modexp precompile.

              if iszero(staticcall(not(0), 0x05, p, 0xc0, p, 0x20)) {

                revert(0, 0)

              }

              res := mload(p)

            }



            function degreeAdjustment(compositionPolynomialDegreeBound, constraintDegree, numeratorDegree,

                                       denominatorDegree) -> res {

              res := sub(sub(compositionPolynomialDegreeBound, 1),

                         sub(add(constraintDegree, numeratorDegree), denominatorDegree))

            }



            {

              // Prepare expmods for denominators and numerators.



              // expmods[0] = point^trace_length.

              mstore(0x4420, expmod(point, /*trace_length*/ mload(0x80), PRIME))



              // expmods[1] = point^(trace_length / 16).

              mstore(0x4440, expmod(point, div(/*trace_length*/ mload(0x80), 16), PRIME))



              // expmods[2] = point^(trace_length / 2).

              mstore(0x4460, expmod(point, div(/*trace_length*/ mload(0x80), 2), PRIME))



              // expmods[3] = point^(trace_length / 8).

              mstore(0x4480, expmod(point, div(/*trace_length*/ mload(0x80), 8), PRIME))



              // expmods[4] = point^(trace_length / 4).

              mstore(0x44a0, expmod(point, div(/*trace_length*/ mload(0x80), 4), PRIME))



              // expmods[5] = point^(trace_length / 256).

              mstore(0x44c0, expmod(point, div(/*trace_length*/ mload(0x80), 256), PRIME))



              // expmods[6] = point^(trace_length / 512).

              mstore(0x44e0, expmod(point, div(/*trace_length*/ mload(0x80), 512), PRIME))



              // expmods[7] = point^(trace_length / 128).

              mstore(0x4500, expmod(point, div(/*trace_length*/ mload(0x80), 128), PRIME))



              // expmods[8] = point^(trace_length / 4096).

              mstore(0x4520, expmod(point, div(/*trace_length*/ mload(0x80), 4096), PRIME))



              // expmods[9] = point^(trace_length / 32).

              mstore(0x4540, expmod(point, div(/*trace_length*/ mload(0x80), 32), PRIME))



              // expmods[10] = point^(trace_length / 8192).

              mstore(0x4560, expmod(point, div(/*trace_length*/ mload(0x80), 8192), PRIME))



              // expmods[11] = trace_generator^(15 * trace_length / 16).

              mstore(0x4580, expmod(/*trace_generator*/ mload(0x3a0), div(mul(15, /*trace_length*/ mload(0x80)), 16), PRIME))



              // expmods[12] = trace_generator^(16 * (trace_length / 16 - 1)).

              mstore(0x45a0, expmod(/*trace_generator*/ mload(0x3a0), mul(16, sub(div(/*trace_length*/ mload(0x80), 16), 1)), PRIME))



              // expmods[13] = trace_generator^(2 * (trace_length / 2 - 1)).

              mstore(0x45c0, expmod(/*trace_generator*/ mload(0x3a0), mul(2, sub(div(/*trace_length*/ mload(0x80), 2), 1)), PRIME))



              // expmods[14] = trace_generator^(4 * (trace_length / 4 - 1)).

              mstore(0x45e0, expmod(/*trace_generator*/ mload(0x3a0), mul(4, sub(div(/*trace_length*/ mload(0x80), 4), 1)), PRIME))



              // expmods[15] = trace_generator^(255 * trace_length / 256).

              mstore(0x4600, expmod(/*trace_generator*/ mload(0x3a0), div(mul(255, /*trace_length*/ mload(0x80)), 256), PRIME))



              // expmods[16] = trace_generator^(63 * trace_length / 64).

              mstore(0x4620, expmod(/*trace_generator*/ mload(0x3a0), div(mul(63, /*trace_length*/ mload(0x80)), 64), PRIME))



              // expmods[17] = trace_generator^(trace_length / 2).

              mstore(0x4640, expmod(/*trace_generator*/ mload(0x3a0), div(/*trace_length*/ mload(0x80), 2), PRIME))



              // expmods[18] = trace_generator^(128 * (trace_length / 128 - 1)).

              mstore(0x4660, expmod(/*trace_generator*/ mload(0x3a0), mul(128, sub(div(/*trace_length*/ mload(0x80), 128), 1)), PRIME))



              // expmods[19] = trace_generator^(251 * trace_length / 256).

              mstore(0x4680, expmod(/*trace_generator*/ mload(0x3a0), div(mul(251, /*trace_length*/ mload(0x80)), 256), PRIME))



              // expmods[20] = trace_generator^(8192 * (trace_length / 8192 - 1)).

              mstore(0x46a0, expmod(/*trace_generator*/ mload(0x3a0), mul(8192, sub(div(/*trace_length*/ mload(0x80), 8192), 1)), PRIME))



              // expmods[21] = trace_generator^(256 * (trace_length / 256 - 1)).

              mstore(0x46c0, expmod(/*trace_generator*/ mload(0x3a0), mul(256, sub(div(/*trace_length*/ mload(0x80), 256), 1)), PRIME))



            }



            {

              // Prepare denominators for batch inverse.



              // Denominator for constraints: 'cpu/decode/opcode_rc/bit', 'pedersen/hash0/ec_subset_sum/booleanity_test', 'pedersen/hash0/ec_subset_sum/add_points/slope', 'pedersen/hash0/ec_subset_sum/add_points/x', 'pedersen/hash0/ec_subset_sum/add_points/y', 'pedersen/hash0/ec_subset_sum/copy_point/x', 'pedersen/hash0/ec_subset_sum/copy_point/y', 'pedersen/hash1/ec_subset_sum/booleanity_test', 'pedersen/hash1/ec_subset_sum/add_points/slope', 'pedersen/hash1/ec_subset_sum/add_points/x', 'pedersen/hash1/ec_subset_sum/add_points/y', 'pedersen/hash1/ec_subset_sum/copy_point/x', 'pedersen/hash1/ec_subset_sum/copy_point/y', 'pedersen/hash2/ec_subset_sum/booleanity_test', 'pedersen/hash2/ec_subset_sum/add_points/slope', 'pedersen/hash2/ec_subset_sum/add_points/x', 'pedersen/hash2/ec_subset_sum/add_points/y', 'pedersen/hash2/ec_subset_sum/copy_point/x', 'pedersen/hash2/ec_subset_sum/copy_point/y', 'pedersen/hash3/ec_subset_sum/booleanity_test', 'pedersen/hash3/ec_subset_sum/add_points/slope', 'pedersen/hash3/ec_subset_sum/add_points/x', 'pedersen/hash3/ec_subset_sum/add_points/y', 'pedersen/hash3/ec_subset_sum/copy_point/x', 'pedersen/hash3/ec_subset_sum/copy_point/y'.

              // denominators[0] = point^trace_length - 1.

              mstore(0x49c0,

                     addmod(/*point^trace_length*/ mload(0x4420), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'cpu/decode/opcode_rc/last_bit'.

              // denominators[1] = point^(trace_length / 16) - trace_generator^(15 * trace_length / 16).

              mstore(0x49e0,

                     addmod(

                       /*point^(trace_length / 16)*/ mload(0x4440),

                       sub(PRIME, /*trace_generator^(15 * trace_length / 16)*/ mload(0x4580)),

                       PRIME))



              // Denominator for constraints: 'cpu/decode/opcode_rc_input', 'cpu/operands/mem_dst_addr', 'cpu/operands/mem0_addr', 'cpu/operands/mem1_addr', 'cpu/operands/ops_mul', 'cpu/operands/res', 'cpu/update_registers/update_pc/tmp0', 'cpu/update_registers/update_pc/tmp1', 'cpu/update_registers/update_pc/pc_cond_negative', 'cpu/update_registers/update_pc/pc_cond_positive', 'cpu/update_registers/update_ap/ap_update', 'cpu/update_registers/update_fp/fp_update', 'cpu/opcodes/call/push_fp', 'cpu/opcodes/call/push_pc', 'cpu/opcodes/assert_eq/assert_eq', 'ecdsa/signature0/doubling_key/slope', 'ecdsa/signature0/doubling_key/x', 'ecdsa/signature0/doubling_key/y', 'ecdsa/signature0/exponentiate_key/booleanity_test', 'ecdsa/signature0/exponentiate_key/add_points/slope', 'ecdsa/signature0/exponentiate_key/add_points/x', 'ecdsa/signature0/exponentiate_key/add_points/y', 'ecdsa/signature0/exponentiate_key/add_points/x_diff_inv', 'ecdsa/signature0/exponentiate_key/copy_point/x', 'ecdsa/signature0/exponentiate_key/copy_point/y'.

              // denominators[2] = point^(trace_length / 16) - 1.

              mstore(0x4a00,

                     addmod(/*point^(trace_length / 16)*/ mload(0x4440), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'initial_ap', 'initial_fp', 'initial_pc', 'memory/multi_column_perm/perm/init0', 'rc16/perm/init0', 'rc16/minimum', 'pedersen/init_addr', 'rc_builtin/init_addr', 'ecdsa/init_addr', 'checkpoints/req_pc_init_addr'.

              // denominators[3] = point - 1.

              mstore(0x4a20,

                     addmod(point, sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'final_ap', 'final_pc'.

              // denominators[4] = point - trace_generator^(16 * (trace_length / 16 - 1)).

              mstore(0x4a40,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(16 * (trace_length / 16 - 1))*/ mload(0x45a0)),

                       PRIME))



              // Denominator for constraints: 'memory/multi_column_perm/perm/step0', 'memory/diff_is_bit', 'memory/is_func'.

              // denominators[5] = point^(trace_length / 2) - 1.

              mstore(0x4a60,

                     addmod(/*point^(trace_length / 2)*/ mload(0x4460), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'memory/multi_column_perm/perm/last'.

              // denominators[6] = point - trace_generator^(2 * (trace_length / 2 - 1)).

              mstore(0x4a80,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(2 * (trace_length / 2 - 1))*/ mload(0x45c0)),

                       PRIME))



              // Denominator for constraints: 'public_memory_addr_zero', 'public_memory_value_zero'.

              // denominators[7] = point^(trace_length / 8) - 1.

              mstore(0x4aa0,

                     addmod(/*point^(trace_length / 8)*/ mload(0x4480), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'rc16/perm/step0', 'rc16/diff_is_bit'.

              // denominators[8] = point^(trace_length / 4) - 1.

              mstore(0x4ac0,

                     addmod(/*point^(trace_length / 4)*/ mload(0x44a0), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'rc16/perm/last', 'rc16/maximum'.

              // denominators[9] = point - trace_generator^(4 * (trace_length / 4 - 1)).

              mstore(0x4ae0,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(4 * (trace_length / 4 - 1))*/ mload(0x45e0)),

                       PRIME))



              // Denominator for constraints: 'pedersen/hash0/ec_subset_sum/bit_extraction_end', 'pedersen/hash1/ec_subset_sum/bit_extraction_end', 'pedersen/hash2/ec_subset_sum/bit_extraction_end', 'pedersen/hash3/ec_subset_sum/bit_extraction_end'.

              // denominators[10] = point^(trace_length / 256) - trace_generator^(63 * trace_length / 64).

              mstore(0x4b00,

                     addmod(

                       /*point^(trace_length / 256)*/ mload(0x44c0),

                       sub(PRIME, /*trace_generator^(63 * trace_length / 64)*/ mload(0x4620)),

                       PRIME))



              // Denominator for constraints: 'pedersen/hash0/ec_subset_sum/zeros_tail', 'pedersen/hash1/ec_subset_sum/zeros_tail', 'pedersen/hash2/ec_subset_sum/zeros_tail', 'pedersen/hash3/ec_subset_sum/zeros_tail'.

              // denominators[11] = point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              mstore(0x4b20,

                     addmod(

                       /*point^(trace_length / 256)*/ mload(0x44c0),

                       sub(PRIME, /*trace_generator^(255 * trace_length / 256)*/ mload(0x4600)),

                       PRIME))



              // Denominator for constraints: 'pedersen/hash0/copy_point/x', 'pedersen/hash0/copy_point/y', 'pedersen/hash1/copy_point/x', 'pedersen/hash1/copy_point/y', 'pedersen/hash2/copy_point/x', 'pedersen/hash2/copy_point/y', 'pedersen/hash3/copy_point/x', 'pedersen/hash3/copy_point/y', 'checkpoints/required_fp_addr', 'checkpoints/required_pc_next_addr', 'checkpoints/req_pc', 'checkpoints/req_fp'.

              // denominators[12] = point^(trace_length / 256) - 1.

              mstore(0x4b40,

                     addmod(/*point^(trace_length / 256)*/ mload(0x44c0), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'pedersen/hash0/init/x', 'pedersen/hash0/init/y', 'pedersen/hash1/init/x', 'pedersen/hash1/init/y', 'pedersen/hash2/init/x', 'pedersen/hash2/init/y', 'pedersen/hash3/init/x', 'pedersen/hash3/init/y', 'pedersen/input0_value0', 'pedersen/input0_value1', 'pedersen/input0_value2', 'pedersen/input0_value3', 'pedersen/input1_value0', 'pedersen/input1_value1', 'pedersen/input1_value2', 'pedersen/input1_value3', 'pedersen/output_value0', 'pedersen/output_value1', 'pedersen/output_value2', 'pedersen/output_value3'.

              // denominators[13] = point^(trace_length / 512) - 1.

              mstore(0x4b60,

                     addmod(/*point^(trace_length / 512)*/ mload(0x44e0), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'pedersen/input0_addr', 'pedersen/input1_addr', 'pedersen/output_addr', 'rc_builtin/value', 'rc_builtin/addr_step'.

              // denominators[14] = point^(trace_length / 128) - 1.

              mstore(0x4b80,

                     addmod(/*point^(trace_length / 128)*/ mload(0x4500), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'ecdsa/signature0/exponentiate_generator/booleanity_test', 'ecdsa/signature0/exponentiate_generator/add_points/slope', 'ecdsa/signature0/exponentiate_generator/add_points/x', 'ecdsa/signature0/exponentiate_generator/add_points/y', 'ecdsa/signature0/exponentiate_generator/add_points/x_diff_inv', 'ecdsa/signature0/exponentiate_generator/copy_point/x', 'ecdsa/signature0/exponentiate_generator/copy_point/y'.

              // denominators[15] = point^(trace_length / 32) - 1.

              mstore(0x4ba0,

                     addmod(/*point^(trace_length / 32)*/ mload(0x4540), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'ecdsa/signature0/exponentiate_generator/bit_extraction_end'.

              // denominators[16] = point^(trace_length / 8192) - trace_generator^(251 * trace_length / 256).

              mstore(0x4bc0,

                     addmod(

                       /*point^(trace_length / 8192)*/ mload(0x4560),

                       sub(PRIME, /*trace_generator^(251 * trace_length / 256)*/ mload(0x4680)),

                       PRIME))



              // Denominator for constraints: 'ecdsa/signature0/exponentiate_generator/zeros_tail'.

              // denominators[17] = point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              mstore(0x4be0,

                     addmod(

                       /*point^(trace_length / 8192)*/ mload(0x4560),

                       sub(PRIME, /*trace_generator^(255 * trace_length / 256)*/ mload(0x4600)),

                       PRIME))



              // Denominator for constraints: 'ecdsa/signature0/exponentiate_key/bit_extraction_end'.

              // denominators[18] = point^(trace_length / 4096) - trace_generator^(251 * trace_length / 256).

              mstore(0x4c00,

                     addmod(

                       /*point^(trace_length / 4096)*/ mload(0x4520),

                       sub(PRIME, /*trace_generator^(251 * trace_length / 256)*/ mload(0x4680)),

                       PRIME))



              // Denominator for constraints: 'ecdsa/signature0/exponentiate_key/zeros_tail'.

              // denominators[19] = point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              mstore(0x4c20,

                     addmod(

                       /*point^(trace_length / 4096)*/ mload(0x4520),

                       sub(PRIME, /*trace_generator^(255 * trace_length / 256)*/ mload(0x4600)),

                       PRIME))



              // Denominator for constraints: 'ecdsa/signature0/init_gen/x', 'ecdsa/signature0/init_gen/y', 'ecdsa/signature0/add_results/slope', 'ecdsa/signature0/add_results/x', 'ecdsa/signature0/add_results/y', 'ecdsa/signature0/add_results/x_diff_inv', 'ecdsa/signature0/extract_r/slope', 'ecdsa/signature0/extract_r/x', 'ecdsa/signature0/extract_r/x_diff_inv', 'ecdsa/signature0/z_nonzero', 'ecdsa/signature0/q_on_curve/x_squared', 'ecdsa/signature0/q_on_curve/on_curve', 'ecdsa/message_addr', 'ecdsa/pubkey_addr', 'ecdsa/message_value0', 'ecdsa/pubkey_value0'.

              // denominators[20] = point^(trace_length / 8192) - 1.

              mstore(0x4c40,

                     addmod(/*point^(trace_length / 8192)*/ mload(0x4560), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'ecdsa/signature0/init_key/x', 'ecdsa/signature0/init_key/y', 'ecdsa/signature0/r_and_w_nonzero'.

              // denominators[21] = point^(trace_length / 4096) - 1.

              mstore(0x4c60,

                     addmod(/*point^(trace_length / 4096)*/ mload(0x4520), sub(PRIME, 1), PRIME))



              // Denominator for constraints: 'checkpoints/req_pc_final_addr'.

              // denominators[22] = point - trace_generator^(256 * (trace_length / 256 - 1)).

              mstore(0x4c80,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(256 * (trace_length / 256 - 1))*/ mload(0x46c0)),

                       PRIME))



            }



            {

              // Compute the inverses of the denominators into denominatorInvs using batch inverse.



              // Start by computing the cumulative product.

              // Let (d_0, d_1, d_2, ..., d_{n-1}) be the values in denominators. After this loop

              // denominatorInvs will be (1, d_0, d_0 * d_1, ...) and prod will contain the value of

              // d_0 * ... * d_{n-1}.

              // Compute the offset between the partialProducts array and the input values array.

              let productsToValuesOffset := 0x2e0

              let prod := 1

              let partialProductEndPtr := 0x49c0

              for { let partialProductPtr := 0x46e0 }

                  lt(partialProductPtr, partialProductEndPtr)

                  { partialProductPtr := add(partialProductPtr, 0x20) } {

                  mstore(partialProductPtr, prod)

                  // prod *= d_{i}.

                  prod := mulmod(prod,

                                 mload(add(partialProductPtr, productsToValuesOffset)),

                                 PRIME)

              }



              let firstPartialProductPtr := 0x46e0

              // Compute the inverse of the product.

              let prodInv := expmod(prod, sub(PRIME, 2), PRIME)



              if eq(prodInv, 0) {

                  // Solidity generates reverts with reason that look as follows:

                  // 1. 4 bytes with the constant 0x08c379a0 (== Keccak256(b'Error(string)')[:4]).

                  // 2. 32 bytes offset bytes (always 0x20 as far as i can tell).

                  // 3. 32 bytes with the length of the revert reason.

                  // 4. Revert reason string.



                  mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)

                  mstore(0x4, 0x20)

                  mstore(0x24, 0x1e)

                  mstore(0x44, "Batch inverse product is zero.")

                  revert(0, 0x62)

              }



              // Compute the inverses.

              // Loop over denominator_invs in reverse order.

              // currentPartialProductPtr is initialized to one past the end.

              let currentPartialProductPtr := 0x49c0

              for { } gt(currentPartialProductPtr, firstPartialProductPtr) { } {

                  currentPartialProductPtr := sub(currentPartialProductPtr, 0x20)

                  // Store 1/d_{i} = (d_0 * ... * d_{i-1}) * 1/(d_0 * ... * d_{i}).

                  mstore(currentPartialProductPtr,

                         mulmod(mload(currentPartialProductPtr), prodInv, PRIME))

                  // Update prodInv to be 1/(d_0 * ... * d_{i-1}) by multiplying by d_i.

                  prodInv := mulmod(prodInv,

                                     mload(add(currentPartialProductPtr, productsToValuesOffset)),

                                     PRIME)

              }

            }



            {

              // Compute numerators and adjustment polynomials.



              // Numerator for constraints 'cpu/decode/opcode_rc/bit'.

              // numerators[0] = point^(trace_length / 16) - trace_generator^(15 * trace_length / 16).

              mstore(0x4ca0,

                     addmod(

                       /*point^(trace_length / 16)*/ mload(0x4440),

                       sub(PRIME, /*trace_generator^(15 * trace_length / 16)*/ mload(0x4580)),

                       PRIME))



              // Numerator for constraints 'cpu/update_registers/update_pc/tmp0', 'cpu/update_registers/update_pc/tmp1', 'cpu/update_registers/update_pc/pc_cond_negative', 'cpu/update_registers/update_pc/pc_cond_positive', 'cpu/update_registers/update_ap/ap_update', 'cpu/update_registers/update_fp/fp_update'.

              // numerators[1] = point - trace_generator^(16 * (trace_length / 16 - 1)).

              mstore(0x4cc0,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(16 * (trace_length / 16 - 1))*/ mload(0x45a0)),

                       PRIME))



              // Numerator for constraints 'memory/multi_column_perm/perm/step0', 'memory/diff_is_bit', 'memory/is_func'.

              // numerators[2] = point - trace_generator^(2 * (trace_length / 2 - 1)).

              mstore(0x4ce0,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(2 * (trace_length / 2 - 1))*/ mload(0x45c0)),

                       PRIME))



              // Numerator for constraints 'rc16/perm/step0', 'rc16/diff_is_bit'.

              // numerators[3] = point - trace_generator^(4 * (trace_length / 4 - 1)).

              mstore(0x4d00,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(4 * (trace_length / 4 - 1))*/ mload(0x45e0)),

                       PRIME))



              // Numerator for constraints 'pedersen/hash0/ec_subset_sum/booleanity_test', 'pedersen/hash0/ec_subset_sum/add_points/slope', 'pedersen/hash0/ec_subset_sum/add_points/x', 'pedersen/hash0/ec_subset_sum/add_points/y', 'pedersen/hash0/ec_subset_sum/copy_point/x', 'pedersen/hash0/ec_subset_sum/copy_point/y', 'pedersen/hash1/ec_subset_sum/booleanity_test', 'pedersen/hash1/ec_subset_sum/add_points/slope', 'pedersen/hash1/ec_subset_sum/add_points/x', 'pedersen/hash1/ec_subset_sum/add_points/y', 'pedersen/hash1/ec_subset_sum/copy_point/x', 'pedersen/hash1/ec_subset_sum/copy_point/y', 'pedersen/hash2/ec_subset_sum/booleanity_test', 'pedersen/hash2/ec_subset_sum/add_points/slope', 'pedersen/hash2/ec_subset_sum/add_points/x', 'pedersen/hash2/ec_subset_sum/add_points/y', 'pedersen/hash2/ec_subset_sum/copy_point/x', 'pedersen/hash2/ec_subset_sum/copy_point/y', 'pedersen/hash3/ec_subset_sum/booleanity_test', 'pedersen/hash3/ec_subset_sum/add_points/slope', 'pedersen/hash3/ec_subset_sum/add_points/x', 'pedersen/hash3/ec_subset_sum/add_points/y', 'pedersen/hash3/ec_subset_sum/copy_point/x', 'pedersen/hash3/ec_subset_sum/copy_point/y'.

              // numerators[4] = point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              mstore(0x4d20,

                     addmod(

                       /*point^(trace_length / 256)*/ mload(0x44c0),

                       sub(PRIME, /*trace_generator^(255 * trace_length / 256)*/ mload(0x4600)),

                       PRIME))



              // Numerator for constraints 'pedersen/hash0/copy_point/x', 'pedersen/hash0/copy_point/y', 'pedersen/hash1/copy_point/x', 'pedersen/hash1/copy_point/y', 'pedersen/hash2/copy_point/x', 'pedersen/hash2/copy_point/y', 'pedersen/hash3/copy_point/x', 'pedersen/hash3/copy_point/y'.

              // numerators[5] = point^(trace_length / 512) - trace_generator^(trace_length / 2).

              mstore(0x4d40,

                     addmod(

                       /*point^(trace_length / 512)*/ mload(0x44e0),

                       sub(PRIME, /*trace_generator^(trace_length / 2)*/ mload(0x4640)),

                       PRIME))



              // Numerator for constraints 'pedersen/input0_addr', 'rc_builtin/addr_step'.

              // numerators[6] = point - trace_generator^(128 * (trace_length / 128 - 1)).

              mstore(0x4d60,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(128 * (trace_length / 128 - 1))*/ mload(0x4660)),

                       PRIME))



              // Numerator for constraints 'ecdsa/signature0/doubling_key/slope', 'ecdsa/signature0/doubling_key/x', 'ecdsa/signature0/doubling_key/y', 'ecdsa/signature0/exponentiate_key/booleanity_test', 'ecdsa/signature0/exponentiate_key/add_points/slope', 'ecdsa/signature0/exponentiate_key/add_points/x', 'ecdsa/signature0/exponentiate_key/add_points/y', 'ecdsa/signature0/exponentiate_key/add_points/x_diff_inv', 'ecdsa/signature0/exponentiate_key/copy_point/x', 'ecdsa/signature0/exponentiate_key/copy_point/y'.

              // numerators[7] = point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              mstore(0x4d80,

                     addmod(

                       /*point^(trace_length / 4096)*/ mload(0x4520),

                       sub(PRIME, /*trace_generator^(255 * trace_length / 256)*/ mload(0x4600)),

                       PRIME))



              // Numerator for constraints 'ecdsa/signature0/exponentiate_generator/booleanity_test', 'ecdsa/signature0/exponentiate_generator/add_points/slope', 'ecdsa/signature0/exponentiate_generator/add_points/x', 'ecdsa/signature0/exponentiate_generator/add_points/y', 'ecdsa/signature0/exponentiate_generator/add_points/x_diff_inv', 'ecdsa/signature0/exponentiate_generator/copy_point/x', 'ecdsa/signature0/exponentiate_generator/copy_point/y'.

              // numerators[8] = point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              mstore(0x4da0,

                     addmod(

                       /*point^(trace_length / 8192)*/ mload(0x4560),

                       sub(PRIME, /*trace_generator^(255 * trace_length / 256)*/ mload(0x4600)),

                       PRIME))



              // Numerator for constraints 'ecdsa/pubkey_addr'.

              // numerators[9] = point - trace_generator^(8192 * (trace_length / 8192 - 1)).

              mstore(0x4dc0,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(8192 * (trace_length / 8192 - 1))*/ mload(0x46a0)),

                       PRIME))



              // Numerator for constraints 'checkpoints/required_pc_next_addr', 'checkpoints/req_pc', 'checkpoints/req_fp'.

              // numerators[10] = point - trace_generator^(256 * (trace_length / 256 - 1)).

              mstore(0x4de0,

                     addmod(

                       point,

                       sub(PRIME, /*trace_generator^(256 * (trace_length / 256 - 1))*/ mload(0x46c0)),

                       PRIME))



              // Adjustment polynomial for constraints 'cpu/decode/opcode_rc/bit'.

              // adjustments[0] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), trace_length / 16, trace_length).

              mstore(0x4e00,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), div(/*trace_length*/ mload(0x80), 16), /*trace_length*/ mload(0x80)), PRIME))



              // Adjustment polynomial for constraints 'cpu/decode/opcode_rc/last_bit', 'cpu/operands/mem_dst_addr', 'cpu/operands/mem0_addr', 'cpu/operands/mem1_addr', 'cpu/operands/ops_mul', 'cpu/operands/res', 'cpu/opcodes/call/push_fp', 'cpu/opcodes/call/push_pc', 'cpu/opcodes/assert_eq/assert_eq'.

              // adjustments[1] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), 0, trace_length / 16).

              mstore(0x4e20,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), 0, div(/*trace_length*/ mload(0x80), 16)), PRIME))



              // Adjustment polynomial for constraints 'cpu/decode/opcode_rc_input'.

              // adjustments[2] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, trace_length / 16).

              mstore(0x4e40,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 0, div(/*trace_length*/ mload(0x80), 16)), PRIME))



              // Adjustment polynomial for constraints 'cpu/update_registers/update_pc/tmp0', 'cpu/update_registers/update_pc/tmp1', 'cpu/update_registers/update_pc/pc_cond_negative', 'cpu/update_registers/update_pc/pc_cond_positive', 'cpu/update_registers/update_ap/ap_update', 'cpu/update_registers/update_fp/fp_update'.

              // adjustments[3] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), 1, trace_length / 16).

              mstore(0x4e60,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), 1, div(/*trace_length*/ mload(0x80), 16)), PRIME))



              // Adjustment polynomial for constraints 'initial_ap', 'initial_fp', 'initial_pc', 'final_ap', 'final_pc', 'memory/multi_column_perm/perm/last', 'rc16/perm/last', 'rc16/minimum', 'rc16/maximum', 'pedersen/init_addr', 'rc_builtin/init_addr', 'ecdsa/init_addr', 'checkpoints/req_pc_init_addr', 'checkpoints/req_pc_final_addr'.

              // adjustments[4] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, 1).

              mstore(0x4e80,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 0, 1), PRIME))



              // Adjustment polynomial for constraints 'memory/multi_column_perm/perm/init0', 'rc16/perm/init0'.

              // adjustments[5] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), 0, 1).

              mstore(0x4ea0,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), 0, 1), PRIME))



              // Adjustment polynomial for constraints 'memory/multi_column_perm/perm/step0', 'memory/diff_is_bit', 'memory/is_func'.

              // adjustments[6] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), 1, trace_length / 2).

              mstore(0x4ec0,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), 1, div(/*trace_length*/ mload(0x80), 2)), PRIME))



              // Adjustment polynomial for constraints 'public_memory_addr_zero', 'public_memory_value_zero'.

              // adjustments[7] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, trace_length / 8).

              mstore(0x4ee0,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 0, div(/*trace_length*/ mload(0x80), 8)), PRIME))



              // Adjustment polynomial for constraints 'rc16/perm/step0', 'rc16/diff_is_bit'.

              // adjustments[8] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), 1, trace_length / 4).

              mstore(0x4f00,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), 1, div(/*trace_length*/ mload(0x80), 4)), PRIME))



              // Adjustment polynomial for constraints 'pedersen/hash0/ec_subset_sum/booleanity_test', 'pedersen/hash0/ec_subset_sum/add_points/slope', 'pedersen/hash0/ec_subset_sum/add_points/x', 'pedersen/hash0/ec_subset_sum/add_points/y', 'pedersen/hash0/ec_subset_sum/copy_point/x', 'pedersen/hash0/ec_subset_sum/copy_point/y', 'pedersen/hash1/ec_subset_sum/booleanity_test', 'pedersen/hash1/ec_subset_sum/add_points/slope', 'pedersen/hash1/ec_subset_sum/add_points/x', 'pedersen/hash1/ec_subset_sum/add_points/y', 'pedersen/hash1/ec_subset_sum/copy_point/x', 'pedersen/hash1/ec_subset_sum/copy_point/y', 'pedersen/hash2/ec_subset_sum/booleanity_test', 'pedersen/hash2/ec_subset_sum/add_points/slope', 'pedersen/hash2/ec_subset_sum/add_points/x', 'pedersen/hash2/ec_subset_sum/add_points/y', 'pedersen/hash2/ec_subset_sum/copy_point/x', 'pedersen/hash2/ec_subset_sum/copy_point/y', 'pedersen/hash3/ec_subset_sum/booleanity_test', 'pedersen/hash3/ec_subset_sum/add_points/slope', 'pedersen/hash3/ec_subset_sum/add_points/x', 'pedersen/hash3/ec_subset_sum/add_points/y', 'pedersen/hash3/ec_subset_sum/copy_point/x', 'pedersen/hash3/ec_subset_sum/copy_point/y'.

              // adjustments[9] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), trace_length / 256, trace_length).

              mstore(0x4f20,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), div(/*trace_length*/ mload(0x80), 256), /*trace_length*/ mload(0x80)), PRIME))



              // Adjustment polynomial for constraints 'pedersen/hash0/ec_subset_sum/bit_extraction_end', 'pedersen/hash0/ec_subset_sum/zeros_tail', 'pedersen/hash1/ec_subset_sum/bit_extraction_end', 'pedersen/hash1/ec_subset_sum/zeros_tail', 'pedersen/hash2/ec_subset_sum/bit_extraction_end', 'pedersen/hash2/ec_subset_sum/zeros_tail', 'pedersen/hash3/ec_subset_sum/bit_extraction_end', 'pedersen/hash3/ec_subset_sum/zeros_tail', 'checkpoints/required_fp_addr'.

              // adjustments[10] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, trace_length / 256).

              mstore(0x4f40,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 0, div(/*trace_length*/ mload(0x80), 256)), PRIME))



              // Adjustment polynomial for constraints 'pedersen/hash0/copy_point/x', 'pedersen/hash0/copy_point/y', 'pedersen/hash1/copy_point/x', 'pedersen/hash1/copy_point/y', 'pedersen/hash2/copy_point/x', 'pedersen/hash2/copy_point/y', 'pedersen/hash3/copy_point/x', 'pedersen/hash3/copy_point/y'.

              // adjustments[11] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, trace_length / 512, trace_length / 256).

              mstore(0x4f60,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), div(/*trace_length*/ mload(0x80), 512), div(/*trace_length*/ mload(0x80), 256)), PRIME))



              // Adjustment polynomial for constraints 'pedersen/hash0/init/x', 'pedersen/hash0/init/y', 'pedersen/hash1/init/x', 'pedersen/hash1/init/y', 'pedersen/hash2/init/x', 'pedersen/hash2/init/y', 'pedersen/hash3/init/x', 'pedersen/hash3/init/y', 'pedersen/input0_value0', 'pedersen/input0_value1', 'pedersen/input0_value2', 'pedersen/input0_value3', 'pedersen/input1_value0', 'pedersen/input1_value1', 'pedersen/input1_value2', 'pedersen/input1_value3', 'pedersen/output_value0', 'pedersen/output_value1', 'pedersen/output_value2', 'pedersen/output_value3'.

              // adjustments[12] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, trace_length / 512).

              mstore(0x4f80,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 0, div(/*trace_length*/ mload(0x80), 512)), PRIME))



              // Adjustment polynomial for constraints 'pedersen/input0_addr', 'rc_builtin/addr_step'.

              // adjustments[13] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 1, trace_length / 128).

              mstore(0x4fa0,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 1, div(/*trace_length*/ mload(0x80), 128)), PRIME))



              // Adjustment polynomial for constraints 'pedersen/input1_addr', 'pedersen/output_addr', 'rc_builtin/value'.

              // adjustments[14] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, trace_length / 128).

              mstore(0x4fc0,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 0, div(/*trace_length*/ mload(0x80), 128)), PRIME))



              // Adjustment polynomial for constraints 'ecdsa/signature0/doubling_key/slope', 'ecdsa/signature0/doubling_key/x', 'ecdsa/signature0/doubling_key/y', 'ecdsa/signature0/exponentiate_key/booleanity_test', 'ecdsa/signature0/exponentiate_key/add_points/slope', 'ecdsa/signature0/exponentiate_key/add_points/x', 'ecdsa/signature0/exponentiate_key/add_points/y', 'ecdsa/signature0/exponentiate_key/add_points/x_diff_inv', 'ecdsa/signature0/exponentiate_key/copy_point/x', 'ecdsa/signature0/exponentiate_key/copy_point/y'.

              // adjustments[15] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), trace_length / 4096, trace_length / 16).

              mstore(0x4fe0,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), div(/*trace_length*/ mload(0x80), 4096), div(/*trace_length*/ mload(0x80), 16)), PRIME))



              // Adjustment polynomial for constraints 'ecdsa/signature0/exponentiate_generator/booleanity_test', 'ecdsa/signature0/exponentiate_generator/add_points/slope', 'ecdsa/signature0/exponentiate_generator/add_points/x', 'ecdsa/signature0/exponentiate_generator/add_points/y', 'ecdsa/signature0/exponentiate_generator/add_points/x_diff_inv', 'ecdsa/signature0/exponentiate_generator/copy_point/x', 'ecdsa/signature0/exponentiate_generator/copy_point/y'.

              // adjustments[16] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), trace_length / 8192, trace_length / 32).

              mstore(0x5000,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), div(/*trace_length*/ mload(0x80), 8192), div(/*trace_length*/ mload(0x80), 32)), PRIME))



              // Adjustment polynomial for constraints 'ecdsa/signature0/exponentiate_generator/bit_extraction_end', 'ecdsa/signature0/exponentiate_generator/zeros_tail', 'ecdsa/signature0/init_gen/x', 'ecdsa/signature0/init_gen/y', 'ecdsa/message_addr', 'ecdsa/message_value0', 'ecdsa/pubkey_value0'.

              // adjustments[17] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, trace_length / 8192).

              mstore(0x5020,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 0, div(/*trace_length*/ mload(0x80), 8192)), PRIME))



              // Adjustment polynomial for constraints 'ecdsa/signature0/exponentiate_key/bit_extraction_end', 'ecdsa/signature0/exponentiate_key/zeros_tail', 'ecdsa/signature0/init_key/x', 'ecdsa/signature0/init_key/y'.

              // adjustments[18] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, trace_length / 4096).

              mstore(0x5040,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 0, div(/*trace_length*/ mload(0x80), 4096)), PRIME))



              // Adjustment polynomial for constraints 'ecdsa/signature0/add_results/slope', 'ecdsa/signature0/add_results/x', 'ecdsa/signature0/add_results/y', 'ecdsa/signature0/add_results/x_diff_inv', 'ecdsa/signature0/extract_r/slope', 'ecdsa/signature0/extract_r/x', 'ecdsa/signature0/extract_r/x_diff_inv', 'ecdsa/signature0/z_nonzero', 'ecdsa/signature0/q_on_curve/x_squared', 'ecdsa/signature0/q_on_curve/on_curve'.

              // adjustments[19] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), 0, trace_length / 8192).

              mstore(0x5060,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), 0, div(/*trace_length*/ mload(0x80), 8192)), PRIME))



              // Adjustment polynomial for constraints 'ecdsa/signature0/r_and_w_nonzero'.

              // adjustments[20] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), 0, trace_length / 4096).

              mstore(0x5080,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), 0, div(/*trace_length*/ mload(0x80), 4096)), PRIME))



              // Adjustment polynomial for constraints 'ecdsa/pubkey_addr'.

              // adjustments[21] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 1, trace_length / 8192).

              mstore(0x50a0,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), sub(/*trace_length*/ mload(0x80), 1), 1, div(/*trace_length*/ mload(0x80), 8192)), PRIME))



              // Adjustment polynomial for constraints 'checkpoints/required_pc_next_addr', 'checkpoints/req_pc', 'checkpoints/req_fp'.

              // adjustments[22] = point^degreeAdjustment(composition_degree_bound, 2 * (trace_length - 1), 1, trace_length / 256).

              mstore(0x50c0,

                     expmod(point, degreeAdjustment(/*composition_degree_bound*/ mload(0x3f20), mul(2, sub(/*trace_length*/ mload(0x80), 1)), 1, div(/*trace_length*/ mload(0x80), 256)), PRIME))



            }



            {

              // Compute the result of the composition polynomial.



              {

              // cpu/decode/opcode_rc/bit_0 = column0_row0 - (column0_row1 + column0_row1).

              let val := addmod(

                /*column0_row0*/ mload(0x2980),

                sub(

                  PRIME,

                  addmod(/*column0_row1*/ mload(0x29a0), /*column0_row1*/ mload(0x29a0), PRIME)),

                PRIME)

              mstore(0x3f40, val)

              }





              {

              // cpu/decode/opcode_rc/bit_1 = column0_row1 - (column0_row2 + column0_row2).

              let val := addmod(

                /*column0_row1*/ mload(0x29a0),

                sub(

                  PRIME,

                  addmod(/*column0_row2*/ mload(0x29c0), /*column0_row2*/ mload(0x29c0), PRIME)),

                PRIME)

              mstore(0x3f60, val)

              }





              {

              // cpu/decode/opcode_rc/bit_2 = column0_row2 - (column0_row3 + column0_row3).

              let val := addmod(

                /*column0_row2*/ mload(0x29c0),

                sub(

                  PRIME,

                  addmod(/*column0_row3*/ mload(0x29e0), /*column0_row3*/ mload(0x29e0), PRIME)),

                PRIME)

              mstore(0x3f80, val)

              }





              {

              // cpu/decode/opcode_rc/bit_4 = column0_row4 - (column0_row5 + column0_row5).

              let val := addmod(

                /*column0_row4*/ mload(0x2a00),

                sub(

                  PRIME,

                  addmod(/*column0_row5*/ mload(0x2a20), /*column0_row5*/ mload(0x2a20), PRIME)),

                PRIME)

              mstore(0x3fa0, val)

              }





              {

              // cpu/decode/opcode_rc/bit_3 = column0_row3 - (column0_row4 + column0_row4).

              let val := addmod(

                /*column0_row3*/ mload(0x29e0),

                sub(

                  PRIME,

                  addmod(/*column0_row4*/ mload(0x2a00), /*column0_row4*/ mload(0x2a00), PRIME)),

                PRIME)

              mstore(0x3fc0, val)

              }





              {

              // cpu/decode/opcode_rc/bit_9 = column0_row9 - (column0_row10 + column0_row10).

              let val := addmod(

                /*column0_row9*/ mload(0x2aa0),

                sub(

                  PRIME,

                  addmod(/*column0_row10*/ mload(0x2ac0), /*column0_row10*/ mload(0x2ac0), PRIME)),

                PRIME)

              mstore(0x3fe0, val)

              }





              {

              // cpu/decode/opcode_rc/bit_5 = column0_row5 - (column0_row6 + column0_row6).

              let val := addmod(

                /*column0_row5*/ mload(0x2a20),

                sub(

                  PRIME,

                  addmod(/*column0_row6*/ mload(0x2a40), /*column0_row6*/ mload(0x2a40), PRIME)),

                PRIME)

              mstore(0x4000, val)

              }





              {

              // cpu/decode/opcode_rc/bit_6 = column0_row6 - (column0_row7 + column0_row7).

              let val := addmod(

                /*column0_row6*/ mload(0x2a40),

                sub(

                  PRIME,

                  addmod(/*column0_row7*/ mload(0x2a60), /*column0_row7*/ mload(0x2a60), PRIME)),

                PRIME)

              mstore(0x4020, val)

              }





              {

              // cpu/decode/opcode_rc/bit_7 = column0_row7 - (column0_row8 + column0_row8).

              let val := addmod(

                /*column0_row7*/ mload(0x2a60),

                sub(

                  PRIME,

                  addmod(/*column0_row8*/ mload(0x2a80), /*column0_row8*/ mload(0x2a80), PRIME)),

                PRIME)

              mstore(0x4040, val)

              }





              {

              // cpu/decode/opcode_rc/bit_8 = column0_row8 - (column0_row9 + column0_row9).

              let val := addmod(

                /*column0_row8*/ mload(0x2a80),

                sub(

                  PRIME,

                  addmod(/*column0_row9*/ mload(0x2aa0), /*column0_row9*/ mload(0x2aa0), PRIME)),

                PRIME)

              mstore(0x4060, val)

              }





              {

              // npc_reg_0 = column17_row0 + cpu__decode__opcode_rc__bit_2 + 1.

              let val := addmod(

                addmod(

                  /*column17_row0*/ mload(0x3200),

                  /*intermediate_value/cpu/decode/opcode_rc/bit_2*/ mload(0x3f80),

                  PRIME),

                1,

                PRIME)

              mstore(0x4080, val)

              }





              {

              // cpu/decode/opcode_rc/bit_10 = column0_row10 - (column0_row11 + column0_row11).

              let val := addmod(

                /*column0_row10*/ mload(0x2ac0),

                sub(

                  PRIME,

                  addmod(/*column0_row11*/ mload(0x2ae0), /*column0_row11*/ mload(0x2ae0), PRIME)),

                PRIME)

              mstore(0x40a0, val)

              }





              {

              // cpu/decode/opcode_rc/bit_11 = column0_row11 - (column0_row12 + column0_row12).

              let val := addmod(

                /*column0_row11*/ mload(0x2ae0),

                sub(

                  PRIME,

                  addmod(/*column0_row12*/ mload(0x2b00), /*column0_row12*/ mload(0x2b00), PRIME)),

                PRIME)

              mstore(0x40c0, val)

              }





              {

              // cpu/decode/opcode_rc/bit_12 = column0_row12 - (column0_row13 + column0_row13).

              let val := addmod(

                /*column0_row12*/ mload(0x2b00),

                sub(

                  PRIME,

                  addmod(/*column0_row13*/ mload(0x2b20), /*column0_row13*/ mload(0x2b20), PRIME)),

                PRIME)

              mstore(0x40e0, val)

              }





              {

              // cpu/decode/opcode_rc/bit_13 = column0_row13 - (column0_row14 + column0_row14).

              let val := addmod(

                /*column0_row13*/ mload(0x2b20),

                sub(

                  PRIME,

                  addmod(/*column0_row14*/ mload(0x2b40), /*column0_row14*/ mload(0x2b40), PRIME)),

                PRIME)

              mstore(0x4100, val)

              }





              {

              // cpu/decode/opcode_rc/bit_14 = column0_row14 - (column0_row15 + column0_row15).

              let val := addmod(

                /*column0_row14*/ mload(0x2b40),

                sub(

                  PRIME,

                  addmod(/*column0_row15*/ mload(0x2b60), /*column0_row15*/ mload(0x2b60), PRIME)),

                PRIME)

              mstore(0x4120, val)

              }





              {

              // memory/address_diff_0 = column18_row2 - column18_row0.

              let val := addmod(/*column18_row2*/ mload(0x3740), sub(PRIME, /*column18_row0*/ mload(0x3700)), PRIME)

              mstore(0x4140, val)

              }





              {

              // rc16/diff_0 = column19_row6 - column19_row2.

              let val := addmod(/*column19_row6*/ mload(0x3840), sub(PRIME, /*column19_row2*/ mload(0x37c0)), PRIME)

              mstore(0x4160, val)

              }





              {

              // pedersen/hash0/ec_subset_sum/bit_0 = column4_row0 - (column4_row1 + column4_row1).

              let val := addmod(

                /*column4_row0*/ mload(0x2cc0),

                sub(

                  PRIME,

                  addmod(/*column4_row1*/ mload(0x2ce0), /*column4_row1*/ mload(0x2ce0), PRIME)),

                PRIME)

              mstore(0x4180, val)

              }





              {

              // pedersen/hash0/ec_subset_sum/bit_neg_0 = 1 - pedersen__hash0__ec_subset_sum__bit_0.

              let val := addmod(

                1,

                sub(PRIME, /*intermediate_value/pedersen/hash0/ec_subset_sum/bit_0*/ mload(0x4180)),

                PRIME)

              mstore(0x41a0, val)

              }





              {

              // pedersen/hash1/ec_subset_sum/bit_0 = column8_row0 - (column8_row1 + column8_row1).

              let val := addmod(

                /*column8_row0*/ mload(0x2e60),

                sub(

                  PRIME,

                  addmod(/*column8_row1*/ mload(0x2e80), /*column8_row1*/ mload(0x2e80), PRIME)),

                PRIME)

              mstore(0x41c0, val)

              }





              {

              // pedersen/hash1/ec_subset_sum/bit_neg_0 = 1 - pedersen__hash1__ec_subset_sum__bit_0.

              let val := addmod(

                1,

                sub(PRIME, /*intermediate_value/pedersen/hash1/ec_subset_sum/bit_0*/ mload(0x41c0)),

                PRIME)

              mstore(0x41e0, val)

              }





              {

              // pedersen/hash2/ec_subset_sum/bit_0 = column12_row0 - (column12_row1 + column12_row1).

              let val := addmod(

                /*column12_row0*/ mload(0x3000),

                sub(

                  PRIME,

                  addmod(/*column12_row1*/ mload(0x3020), /*column12_row1*/ mload(0x3020), PRIME)),

                PRIME)

              mstore(0x4200, val)

              }





              {

              // pedersen/hash2/ec_subset_sum/bit_neg_0 = 1 - pedersen__hash2__ec_subset_sum__bit_0.

              let val := addmod(

                1,

                sub(PRIME, /*intermediate_value/pedersen/hash2/ec_subset_sum/bit_0*/ mload(0x4200)),

                PRIME)

              mstore(0x4220, val)

              }





              {

              // pedersen/hash3/ec_subset_sum/bit_0 = column16_row0 - (column16_row1 + column16_row1).

              let val := addmod(

                /*column16_row0*/ mload(0x31a0),

                sub(

                  PRIME,

                  addmod(/*column16_row1*/ mload(0x31c0), /*column16_row1*/ mload(0x31c0), PRIME)),

                PRIME)

              mstore(0x4240, val)

              }





              {

              // pedersen/hash3/ec_subset_sum/bit_neg_0 = 1 - pedersen__hash3__ec_subset_sum__bit_0.

              let val := addmod(

                1,

                sub(PRIME, /*intermediate_value/pedersen/hash3/ec_subset_sum/bit_0*/ mload(0x4240)),

                PRIME)

              mstore(0x4260, val)

              }





              {

              // rc_builtin/value0_0 = column19_row12.

              let val := /*column19_row12*/ mload(0x38e0)

              mstore(0x4280, val)

              }





              {

              // rc_builtin/value1_0 = rc_builtin__value0_0 * offset_size + column19_row28.

              let val := addmod(

                mulmod(

                  /*intermediate_value/rc_builtin/value0_0*/ mload(0x4280),

                  /*offset_size*/ mload(0xa0),

                  PRIME),

                /*column19_row28*/ mload(0x39a0),

                PRIME)

              mstore(0x42a0, val)

              }





              {

              // rc_builtin/value2_0 = rc_builtin__value1_0 * offset_size + column19_row44.

              let val := addmod(

                mulmod(

                  /*intermediate_value/rc_builtin/value1_0*/ mload(0x42a0),

                  /*offset_size*/ mload(0xa0),

                  PRIME),

                /*column19_row44*/ mload(0x39e0),

                PRIME)

              mstore(0x42c0, val)

              }





              {

              // rc_builtin/value3_0 = rc_builtin__value2_0 * offset_size + column19_row60.

              let val := addmod(

                mulmod(

                  /*intermediate_value/rc_builtin/value2_0*/ mload(0x42c0),

                  /*offset_size*/ mload(0xa0),

                  PRIME),

                /*column19_row60*/ mload(0x3a00),

                PRIME)

              mstore(0x42e0, val)

              }





              {

              // rc_builtin/value4_0 = rc_builtin__value3_0 * offset_size + column19_row76.

              let val := addmod(

                mulmod(

                  /*intermediate_value/rc_builtin/value3_0*/ mload(0x42e0),

                  /*offset_size*/ mload(0xa0),

                  PRIME),

                /*column19_row76*/ mload(0x3a20),

                PRIME)

              mstore(0x4300, val)

              }





              {

              // rc_builtin/value5_0 = rc_builtin__value4_0 * offset_size + column19_row92.

              let val := addmod(

                mulmod(

                  /*intermediate_value/rc_builtin/value4_0*/ mload(0x4300),

                  /*offset_size*/ mload(0xa0),

                  PRIME),

                /*column19_row92*/ mload(0x3a40),

                PRIME)

              mstore(0x4320, val)

              }





              {

              // rc_builtin/value6_0 = rc_builtin__value5_0 * offset_size + column19_row108.

              let val := addmod(

                mulmod(

                  /*intermediate_value/rc_builtin/value5_0*/ mload(0x4320),

                  /*offset_size*/ mload(0xa0),

                  PRIME),

                /*column19_row108*/ mload(0x3a60),

                PRIME)

              mstore(0x4340, val)

              }





              {

              // rc_builtin/value7_0 = rc_builtin__value6_0 * offset_size + column19_row124.

              let val := addmod(

                mulmod(

                  /*intermediate_value/rc_builtin/value6_0*/ mload(0x4340),

                  /*offset_size*/ mload(0xa0),

                  PRIME),

                /*column19_row124*/ mload(0x3a80),

                PRIME)

              mstore(0x4360, val)

              }





              {

              // ecdsa/signature0/doubling_key/x_squared = column19_row7 * column19_row7.

              let val := mulmod(/*column19_row7*/ mload(0x3860), /*column19_row7*/ mload(0x3860), PRIME)

              mstore(0x4380, val)

              }





              {

              // ecdsa/signature0/exponentiate_generator/bit_0 = column20_row30 - (column20_row62 + column20_row62).

              let val := addmod(

                /*column20_row30*/ mload(0x3c80),

                sub(

                  PRIME,

                  addmod(/*column20_row62*/ mload(0x3ce0), /*column20_row62*/ mload(0x3ce0), PRIME)),

                PRIME)

              mstore(0x43a0, val)

              }





              {

              // ecdsa/signature0/exponentiate_generator/bit_neg_0 = 1 - ecdsa__signature0__exponentiate_generator__bit_0.

              let val := addmod(

                1,

                sub(

                  PRIME,

                  /*intermediate_value/ecdsa/signature0/exponentiate_generator/bit_0*/ mload(0x43a0)),

                PRIME)

              mstore(0x43c0, val)

              }





              {

              // ecdsa/signature0/exponentiate_key/bit_0 = column20_row2 - (column20_row18 + column20_row18).

              let val := addmod(

                /*column20_row2*/ mload(0x3b20),

                sub(

                  PRIME,

                  addmod(/*column20_row18*/ mload(0x3c00), /*column20_row18*/ mload(0x3c00), PRIME)),

                PRIME)

              mstore(0x43e0, val)

              }





              {

              // ecdsa/signature0/exponentiate_key/bit_neg_0 = 1 - ecdsa__signature0__exponentiate_key__bit_0.

              let val := addmod(

                1,

                sub(

                  PRIME,

                  /*intermediate_value/ecdsa/signature0/exponentiate_key/bit_0*/ mload(0x43e0)),

                PRIME)

              mstore(0x4400, val)

              }





              {

              // Constraint expression for cpu/decode/opcode_rc/bit: cpu__decode__opcode_rc__bit_0 * cpu__decode__opcode_rc__bit_0 - cpu__decode__opcode_rc__bit_0.

              let val := addmod(

                mulmod(

                  /*intermediate_value/cpu/decode/opcode_rc/bit_0*/ mload(0x3f40),

                  /*intermediate_value/cpu/decode/opcode_rc/bit_0*/ mload(0x3f40),

                  PRIME),

                sub(PRIME, /*intermediate_value/cpu/decode/opcode_rc/bit_0*/ mload(0x3f40)),

                PRIME)



              // Numerator: point^(trace_length / 16) - trace_generator^(15 * trace_length / 16).

              // val *= numerators[0].

              val := mulmod(val, mload(0x4ca0), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[0] + coefficients[1] * adjustments[0]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[0]*/ mload(0x440),

                                       mulmod(/*coefficients[1]*/ mload(0x460),

                                              /*adjustments[0]*/mload(0x4e00),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/decode/opcode_rc/last_bit: column0_row0 * column0_row0 - column0_row0.

              let val := addmod(

                mulmod(/*column0_row0*/ mload(0x2980), /*column0_row0*/ mload(0x2980), PRIME),

                sub(PRIME, /*column0_row0*/ mload(0x2980)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - trace_generator^(15 * trace_length / 16).

              // val *= denominator_invs[1].

              val := mulmod(val, mload(0x4700), PRIME)



              // res += val * (coefficients[2] + coefficients[3] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[2]*/ mload(0x480),

                                       mulmod(/*coefficients[3]*/ mload(0x4a0),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/decode/opcode_rc_input: column17_row1 - (((column0_row0 * offset_size + column19_row4) * offset_size + column19_row8) * offset_size + column19_row0).

              let val := addmod(

                /*column17_row1*/ mload(0x3220),

                sub(

                  PRIME,

                  addmod(

                    mulmod(

                      addmod(

                        mulmod(

                          addmod(

                            mulmod(/*column0_row0*/ mload(0x2980), /*offset_size*/ mload(0xa0), PRIME),

                            /*column19_row4*/ mload(0x3800),

                            PRIME),

                          /*offset_size*/ mload(0xa0),

                          PRIME),

                        /*column19_row8*/ mload(0x3880),

                        PRIME),

                      /*offset_size*/ mload(0xa0),

                      PRIME),

                    /*column19_row0*/ mload(0x3780),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[4] + coefficients[5] * adjustments[2]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[4]*/ mload(0x4c0),

                                       mulmod(/*coefficients[5]*/ mload(0x4e0),

                                              /*adjustments[2]*/mload(0x4e40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/operands/mem_dst_addr: column17_row8 + half_offset_size - (cpu__decode__opcode_rc__bit_0 * column19_row9 + (1 - cpu__decode__opcode_rc__bit_0) * column19_row1 + column19_row0).

              let val := addmod(

                addmod(/*column17_row8*/ mload(0x3300), /*half_offset_size*/ mload(0xc0), PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      mulmod(

                        /*intermediate_value/cpu/decode/opcode_rc/bit_0*/ mload(0x3f40),

                        /*column19_row9*/ mload(0x38a0),

                        PRIME),

                      mulmod(

                        addmod(

                          1,

                          sub(PRIME, /*intermediate_value/cpu/decode/opcode_rc/bit_0*/ mload(0x3f40)),

                          PRIME),

                        /*column19_row1*/ mload(0x37a0),

                        PRIME),

                      PRIME),

                    /*column19_row0*/ mload(0x3780),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[6] + coefficients[7] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[6]*/ mload(0x500),

                                       mulmod(/*coefficients[7]*/ mload(0x520),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/operands/mem0_addr: column17_row4 + half_offset_size - (cpu__decode__opcode_rc__bit_1 * column19_row9 + (1 - cpu__decode__opcode_rc__bit_1) * column19_row1 + column19_row8).

              let val := addmod(

                addmod(/*column17_row4*/ mload(0x3280), /*half_offset_size*/ mload(0xc0), PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      mulmod(

                        /*intermediate_value/cpu/decode/opcode_rc/bit_1*/ mload(0x3f60),

                        /*column19_row9*/ mload(0x38a0),

                        PRIME),

                      mulmod(

                        addmod(

                          1,

                          sub(PRIME, /*intermediate_value/cpu/decode/opcode_rc/bit_1*/ mload(0x3f60)),

                          PRIME),

                        /*column19_row1*/ mload(0x37a0),

                        PRIME),

                      PRIME),

                    /*column19_row8*/ mload(0x3880),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[8] + coefficients[9] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[8]*/ mload(0x540),

                                       mulmod(/*coefficients[9]*/ mload(0x560),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/operands/mem1_addr: column17_row12 + half_offset_size - (cpu__decode__opcode_rc__bit_2 * column17_row0 + cpu__decode__opcode_rc__bit_4 * column19_row1 + cpu__decode__opcode_rc__bit_3 * column19_row9 + (1 - (cpu__decode__opcode_rc__bit_2 + cpu__decode__opcode_rc__bit_4 + cpu__decode__opcode_rc__bit_3)) * column17_row5 + column19_row4).

              let val := addmod(

                addmod(/*column17_row12*/ mload(0x3340), /*half_offset_size*/ mload(0xc0), PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      addmod(

                        addmod(

                          mulmod(

                            /*intermediate_value/cpu/decode/opcode_rc/bit_2*/ mload(0x3f80),

                            /*column17_row0*/ mload(0x3200),

                            PRIME),

                          mulmod(

                            /*intermediate_value/cpu/decode/opcode_rc/bit_4*/ mload(0x3fa0),

                            /*column19_row1*/ mload(0x37a0),

                            PRIME),

                          PRIME),

                        mulmod(

                          /*intermediate_value/cpu/decode/opcode_rc/bit_3*/ mload(0x3fc0),

                          /*column19_row9*/ mload(0x38a0),

                          PRIME),

                        PRIME),

                      mulmod(

                        addmod(

                          1,

                          sub(

                            PRIME,

                            addmod(

                              addmod(

                                /*intermediate_value/cpu/decode/opcode_rc/bit_2*/ mload(0x3f80),

                                /*intermediate_value/cpu/decode/opcode_rc/bit_4*/ mload(0x3fa0),

                                PRIME),

                              /*intermediate_value/cpu/decode/opcode_rc/bit_3*/ mload(0x3fc0),

                              PRIME)),

                          PRIME),

                        /*column17_row5*/ mload(0x32a0),

                        PRIME),

                      PRIME),

                    /*column19_row4*/ mload(0x3800),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[10] + coefficients[11] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[10]*/ mload(0x580),

                                       mulmod(/*coefficients[11]*/ mload(0x5a0),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/operands/ops_mul: column19_row5 - column17_row5 * column17_row13.

              let val := addmod(

                /*column19_row5*/ mload(0x3820),

                sub(

                  PRIME,

                  mulmod(/*column17_row5*/ mload(0x32a0), /*column17_row13*/ mload(0x3360), PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[12] + coefficients[13] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[12]*/ mload(0x5c0),

                                       mulmod(/*coefficients[13]*/ mload(0x5e0),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/operands/res: (1 - cpu__decode__opcode_rc__bit_9) * column19_row13 - (cpu__decode__opcode_rc__bit_5 * (column17_row5 + column17_row13) + cpu__decode__opcode_rc__bit_6 * column19_row5 + (1 - (cpu__decode__opcode_rc__bit_5 + cpu__decode__opcode_rc__bit_6 + cpu__decode__opcode_rc__bit_9)) * column17_row13).

              let val := addmod(

                mulmod(

                  addmod(

                    1,

                    sub(PRIME, /*intermediate_value/cpu/decode/opcode_rc/bit_9*/ mload(0x3fe0)),

                    PRIME),

                  /*column19_row13*/ mload(0x3900),

                  PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      mulmod(

                        /*intermediate_value/cpu/decode/opcode_rc/bit_5*/ mload(0x4000),

                        addmod(/*column17_row5*/ mload(0x32a0), /*column17_row13*/ mload(0x3360), PRIME),

                        PRIME),

                      mulmod(

                        /*intermediate_value/cpu/decode/opcode_rc/bit_6*/ mload(0x4020),

                        /*column19_row5*/ mload(0x3820),

                        PRIME),

                      PRIME),

                    mulmod(

                      addmod(

                        1,

                        sub(

                          PRIME,

                          addmod(

                            addmod(

                              /*intermediate_value/cpu/decode/opcode_rc/bit_5*/ mload(0x4000),

                              /*intermediate_value/cpu/decode/opcode_rc/bit_6*/ mload(0x4020),

                              PRIME),

                            /*intermediate_value/cpu/decode/opcode_rc/bit_9*/ mload(0x3fe0),

                            PRIME)),

                        PRIME),

                      /*column17_row13*/ mload(0x3360),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[14] + coefficients[15] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[14]*/ mload(0x600),

                                       mulmod(/*coefficients[15]*/ mload(0x620),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/update_registers/update_pc/tmp0: column19_row3 - cpu__decode__opcode_rc__bit_9 * column17_row9.

              let val := addmod(

                /*column19_row3*/ mload(0x37e0),

                sub(

                  PRIME,

                  mulmod(

                    /*intermediate_value/cpu/decode/opcode_rc/bit_9*/ mload(0x3fe0),

                    /*column17_row9*/ mload(0x3320),

                    PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(16 * (trace_length / 16 - 1)).

              // val *= numerators[1].

              val := mulmod(val, mload(0x4cc0), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[16] + coefficients[17] * adjustments[3]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[16]*/ mload(0x640),

                                       mulmod(/*coefficients[17]*/ mload(0x660),

                                              /*adjustments[3]*/mload(0x4e60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/update_registers/update_pc/tmp1: column19_row11 - column19_row3 * column19_row13.

              let val := addmod(

                /*column19_row11*/ mload(0x38c0),

                sub(

                  PRIME,

                  mulmod(/*column19_row3*/ mload(0x37e0), /*column19_row13*/ mload(0x3900), PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(16 * (trace_length / 16 - 1)).

              // val *= numerators[1].

              val := mulmod(val, mload(0x4cc0), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[18] + coefficients[19] * adjustments[3]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[18]*/ mload(0x680),

                                       mulmod(/*coefficients[19]*/ mload(0x6a0),

                                              /*adjustments[3]*/mload(0x4e60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/update_registers/update_pc/pc_cond_negative: (1 - cpu__decode__opcode_rc__bit_9) * column17_row16 + column19_row3 * (column17_row16 - (column17_row0 + column17_row13)) - ((1 - (cpu__decode__opcode_rc__bit_7 + cpu__decode__opcode_rc__bit_8 + cpu__decode__opcode_rc__bit_9)) * npc_reg_0 + cpu__decode__opcode_rc__bit_7 * column19_row13 + cpu__decode__opcode_rc__bit_8 * (column17_row0 + column19_row13)).

              let val := addmod(

                addmod(

                  mulmod(

                    addmod(

                      1,

                      sub(PRIME, /*intermediate_value/cpu/decode/opcode_rc/bit_9*/ mload(0x3fe0)),

                      PRIME),

                    /*column17_row16*/ mload(0x3380),

                    PRIME),

                  mulmod(

                    /*column19_row3*/ mload(0x37e0),

                    addmod(

                      /*column17_row16*/ mload(0x3380),

                      sub(

                        PRIME,

                        addmod(/*column17_row0*/ mload(0x3200), /*column17_row13*/ mload(0x3360), PRIME)),

                      PRIME),

                    PRIME),

                  PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      mulmod(

                        addmod(

                          1,

                          sub(

                            PRIME,

                            addmod(

                              addmod(

                                /*intermediate_value/cpu/decode/opcode_rc/bit_7*/ mload(0x4040),

                                /*intermediate_value/cpu/decode/opcode_rc/bit_8*/ mload(0x4060),

                                PRIME),

                              /*intermediate_value/cpu/decode/opcode_rc/bit_9*/ mload(0x3fe0),

                              PRIME)),

                          PRIME),

                        /*intermediate_value/npc_reg_0*/ mload(0x4080),

                        PRIME),

                      mulmod(

                        /*intermediate_value/cpu/decode/opcode_rc/bit_7*/ mload(0x4040),

                        /*column19_row13*/ mload(0x3900),

                        PRIME),

                      PRIME),

                    mulmod(

                      /*intermediate_value/cpu/decode/opcode_rc/bit_8*/ mload(0x4060),

                      addmod(/*column17_row0*/ mload(0x3200), /*column19_row13*/ mload(0x3900), PRIME),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(16 * (trace_length / 16 - 1)).

              // val *= numerators[1].

              val := mulmod(val, mload(0x4cc0), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[20] + coefficients[21] * adjustments[3]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[20]*/ mload(0x6c0),

                                       mulmod(/*coefficients[21]*/ mload(0x6e0),

                                              /*adjustments[3]*/mload(0x4e60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/update_registers/update_pc/pc_cond_positive: (column19_row11 - cpu__decode__opcode_rc__bit_9) * (column17_row16 - npc_reg_0).

              let val := mulmod(

                addmod(

                  /*column19_row11*/ mload(0x38c0),

                  sub(PRIME, /*intermediate_value/cpu/decode/opcode_rc/bit_9*/ mload(0x3fe0)),

                  PRIME),

                addmod(

                  /*column17_row16*/ mload(0x3380),

                  sub(PRIME, /*intermediate_value/npc_reg_0*/ mload(0x4080)),

                  PRIME),

                PRIME)



              // Numerator: point - trace_generator^(16 * (trace_length / 16 - 1)).

              // val *= numerators[1].

              val := mulmod(val, mload(0x4cc0), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[22] + coefficients[23] * adjustments[3]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[22]*/ mload(0x700),

                                       mulmod(/*coefficients[23]*/ mload(0x720),

                                              /*adjustments[3]*/mload(0x4e60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/update_registers/update_ap/ap_update: column19_row17 - (column19_row1 + cpu__decode__opcode_rc__bit_10 * column19_row13 + cpu__decode__opcode_rc__bit_11 + cpu__decode__opcode_rc__bit_12 * 2).

              let val := addmod(

                /*column19_row17*/ mload(0x3940),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      addmod(

                        /*column19_row1*/ mload(0x37a0),

                        mulmod(

                          /*intermediate_value/cpu/decode/opcode_rc/bit_10*/ mload(0x40a0),

                          /*column19_row13*/ mload(0x3900),

                          PRIME),

                        PRIME),

                      /*intermediate_value/cpu/decode/opcode_rc/bit_11*/ mload(0x40c0),

                      PRIME),

                    mulmod(/*intermediate_value/cpu/decode/opcode_rc/bit_12*/ mload(0x40e0), 2, PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(16 * (trace_length / 16 - 1)).

              // val *= numerators[1].

              val := mulmod(val, mload(0x4cc0), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[24] + coefficients[25] * adjustments[3]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[24]*/ mload(0x740),

                                       mulmod(/*coefficients[25]*/ mload(0x760),

                                              /*adjustments[3]*/mload(0x4e60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/update_registers/update_fp/fp_update: column19_row25 - ((1 - (cpu__decode__opcode_rc__bit_12 + cpu__decode__opcode_rc__bit_13)) * column19_row9 + cpu__decode__opcode_rc__bit_13 * column17_row9 + cpu__decode__opcode_rc__bit_12 * (column19_row1 + 2)).

              let val := addmod(

                /*column19_row25*/ mload(0x3980),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      mulmod(

                        addmod(

                          1,

                          sub(

                            PRIME,

                            addmod(

                              /*intermediate_value/cpu/decode/opcode_rc/bit_12*/ mload(0x40e0),

                              /*intermediate_value/cpu/decode/opcode_rc/bit_13*/ mload(0x4100),

                              PRIME)),

                          PRIME),

                        /*column19_row9*/ mload(0x38a0),

                        PRIME),

                      mulmod(

                        /*intermediate_value/cpu/decode/opcode_rc/bit_13*/ mload(0x4100),

                        /*column17_row9*/ mload(0x3320),

                        PRIME),

                      PRIME),

                    mulmod(

                      /*intermediate_value/cpu/decode/opcode_rc/bit_12*/ mload(0x40e0),

                      addmod(/*column19_row1*/ mload(0x37a0), 2, PRIME),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(16 * (trace_length / 16 - 1)).

              // val *= numerators[1].

              val := mulmod(val, mload(0x4cc0), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[26] + coefficients[27] * adjustments[3]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[26]*/ mload(0x780),

                                       mulmod(/*coefficients[27]*/ mload(0x7a0),

                                              /*adjustments[3]*/mload(0x4e60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/opcodes/call/push_fp: cpu__decode__opcode_rc__bit_12 * (column17_row9 - column19_row9).

              let val := mulmod(

                /*intermediate_value/cpu/decode/opcode_rc/bit_12*/ mload(0x40e0),

                addmod(/*column17_row9*/ mload(0x3320), sub(PRIME, /*column19_row9*/ mload(0x38a0)), PRIME),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[28] + coefficients[29] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[28]*/ mload(0x7c0),

                                       mulmod(/*coefficients[29]*/ mload(0x7e0),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/opcodes/call/push_pc: cpu__decode__opcode_rc__bit_12 * (column17_row5 - (column17_row0 + cpu__decode__opcode_rc__bit_2 + 1)).

              let val := mulmod(

                /*intermediate_value/cpu/decode/opcode_rc/bit_12*/ mload(0x40e0),

                addmod(

                  /*column17_row5*/ mload(0x32a0),

                  sub(

                    PRIME,

                    addmod(

                      addmod(

                        /*column17_row0*/ mload(0x3200),

                        /*intermediate_value/cpu/decode/opcode_rc/bit_2*/ mload(0x3f80),

                        PRIME),

                      1,

                      PRIME)),

                  PRIME),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[30] + coefficients[31] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[30]*/ mload(0x800),

                                       mulmod(/*coefficients[31]*/ mload(0x820),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for cpu/opcodes/assert_eq/assert_eq: cpu__decode__opcode_rc__bit_14 * (column17_row9 - column19_row13).

              let val := mulmod(

                /*intermediate_value/cpu/decode/opcode_rc/bit_14*/ mload(0x4120),

                addmod(

                  /*column17_row9*/ mload(0x3320),

                  sub(PRIME, /*column19_row13*/ mload(0x3900)),

                  PRIME),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[32] + coefficients[33] * adjustments[1]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[32]*/ mload(0x840),

                                       mulmod(/*coefficients[33]*/ mload(0x860),

                                              /*adjustments[1]*/mload(0x4e20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for initial_ap: column19_row1 - initial_ap.

              let val := addmod(/*column19_row1*/ mload(0x37a0), sub(PRIME, /*initial_ap*/ mload(0xe0)), PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[34] + coefficients[35] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[34]*/ mload(0x880),

                                       mulmod(/*coefficients[35]*/ mload(0x8a0),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for initial_fp: column19_row9 - initial_ap.

              let val := addmod(/*column19_row9*/ mload(0x38a0), sub(PRIME, /*initial_ap*/ mload(0xe0)), PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[36] + coefficients[37] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[36]*/ mload(0x8c0),

                                       mulmod(/*coefficients[37]*/ mload(0x8e0),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for initial_pc: column17_row0 - initial_pc.

              let val := addmod(/*column17_row0*/ mload(0x3200), sub(PRIME, /*initial_pc*/ mload(0x100)), PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[38] + coefficients[39] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[38]*/ mload(0x900),

                                       mulmod(/*coefficients[39]*/ mload(0x920),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for final_ap: column19_row1 - final_ap.

              let val := addmod(/*column19_row1*/ mload(0x37a0), sub(PRIME, /*final_ap*/ mload(0x120)), PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - trace_generator^(16 * (trace_length / 16 - 1)).

              // val *= denominator_invs[4].

              val := mulmod(val, mload(0x4760), PRIME)



              // res += val * (coefficients[40] + coefficients[41] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[40]*/ mload(0x940),

                                       mulmod(/*coefficients[41]*/ mload(0x960),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for final_pc: column17_row0 - final_pc.

              let val := addmod(/*column17_row0*/ mload(0x3200), sub(PRIME, /*final_pc*/ mload(0x140)), PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - trace_generator^(16 * (trace_length / 16 - 1)).

              // val *= denominator_invs[4].

              val := mulmod(val, mload(0x4760), PRIME)



              // res += val * (coefficients[42] + coefficients[43] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[42]*/ mload(0x980),

                                       mulmod(/*coefficients[43]*/ mload(0x9a0),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for memory/multi_column_perm/perm/init0: (memory/multi_column_perm/perm/interaction_elm - (column18_row0 + memory/multi_column_perm/hash_interaction_elm0 * column18_row1)) * column21_inter1_row0 + column17_row0 + memory/multi_column_perm/hash_interaction_elm0 * column17_row1 - memory/multi_column_perm/perm/interaction_elm.

              let val := addmod(

                addmod(

                  addmod(

                    mulmod(

                      addmod(

                        /*memory/multi_column_perm/perm/interaction_elm*/ mload(0x160),

                        sub(

                          PRIME,

                          addmod(

                            /*column18_row0*/ mload(0x3700),

                            mulmod(

                              /*memory/multi_column_perm/hash_interaction_elm0*/ mload(0x180),

                              /*column18_row1*/ mload(0x3720),

                              PRIME),

                            PRIME)),

                        PRIME),

                      /*column21_inter1_row0*/ mload(0x3ea0),

                      PRIME),

                    /*column17_row0*/ mload(0x3200),

                    PRIME),

                  mulmod(

                    /*memory/multi_column_perm/hash_interaction_elm0*/ mload(0x180),

                    /*column17_row1*/ mload(0x3220),

                    PRIME),

                  PRIME),

                sub(PRIME, /*memory/multi_column_perm/perm/interaction_elm*/ mload(0x160)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[44] + coefficients[45] * adjustments[5]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[44]*/ mload(0x9c0),

                                       mulmod(/*coefficients[45]*/ mload(0x9e0),

                                              /*adjustments[5]*/mload(0x4ea0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for memory/multi_column_perm/perm/step0: (memory/multi_column_perm/perm/interaction_elm - (column18_row2 + memory/multi_column_perm/hash_interaction_elm0 * column18_row3)) * column21_inter1_row2 - (memory/multi_column_perm/perm/interaction_elm - (column17_row2 + memory/multi_column_perm/hash_interaction_elm0 * column17_row3)) * column21_inter1_row0.

              let val := addmod(

                mulmod(

                  addmod(

                    /*memory/multi_column_perm/perm/interaction_elm*/ mload(0x160),

                    sub(

                      PRIME,

                      addmod(

                        /*column18_row2*/ mload(0x3740),

                        mulmod(

                          /*memory/multi_column_perm/hash_interaction_elm0*/ mload(0x180),

                          /*column18_row3*/ mload(0x3760),

                          PRIME),

                        PRIME)),

                    PRIME),

                  /*column21_inter1_row2*/ mload(0x3ee0),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    addmod(

                      /*memory/multi_column_perm/perm/interaction_elm*/ mload(0x160),

                      sub(

                        PRIME,

                        addmod(

                          /*column17_row2*/ mload(0x3240),

                          mulmod(

                            /*memory/multi_column_perm/hash_interaction_elm0*/ mload(0x180),

                            /*column17_row3*/ mload(0x3260),

                            PRIME),

                          PRIME)),

                      PRIME),

                    /*column21_inter1_row0*/ mload(0x3ea0),

                    PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(2 * (trace_length / 2 - 1)).

              // val *= numerators[2].

              val := mulmod(val, mload(0x4ce0), PRIME)

              // Denominator: point^(trace_length / 2) - 1.

              // val *= denominator_invs[5].

              val := mulmod(val, mload(0x4780), PRIME)



              // res += val * (coefficients[46] + coefficients[47] * adjustments[6]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[46]*/ mload(0xa00),

                                       mulmod(/*coefficients[47]*/ mload(0xa20),

                                              /*adjustments[6]*/mload(0x4ec0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for memory/multi_column_perm/perm/last: column21_inter1_row0 - memory/multi_column_perm/perm/public_memory_prod.

              let val := addmod(

                /*column21_inter1_row0*/ mload(0x3ea0),

                sub(PRIME, /*memory/multi_column_perm/perm/public_memory_prod*/ mload(0x1a0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - trace_generator^(2 * (trace_length / 2 - 1)).

              // val *= denominator_invs[6].

              val := mulmod(val, mload(0x47a0), PRIME)



              // res += val * (coefficients[48] + coefficients[49] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[48]*/ mload(0xa40),

                                       mulmod(/*coefficients[49]*/ mload(0xa60),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for memory/diff_is_bit: memory__address_diff_0 * memory__address_diff_0 - memory__address_diff_0.

              let val := addmod(

                mulmod(

                  /*intermediate_value/memory/address_diff_0*/ mload(0x4140),

                  /*intermediate_value/memory/address_diff_0*/ mload(0x4140),

                  PRIME),

                sub(PRIME, /*intermediate_value/memory/address_diff_0*/ mload(0x4140)),

                PRIME)



              // Numerator: point - trace_generator^(2 * (trace_length / 2 - 1)).

              // val *= numerators[2].

              val := mulmod(val, mload(0x4ce0), PRIME)

              // Denominator: point^(trace_length / 2) - 1.

              // val *= denominator_invs[5].

              val := mulmod(val, mload(0x4780), PRIME)



              // res += val * (coefficients[50] + coefficients[51] * adjustments[6]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[50]*/ mload(0xa80),

                                       mulmod(/*coefficients[51]*/ mload(0xaa0),

                                              /*adjustments[6]*/mload(0x4ec0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for memory/is_func: (memory__address_diff_0 - 1) * (column18_row1 - column18_row3).

              let val := mulmod(

                addmod(/*intermediate_value/memory/address_diff_0*/ mload(0x4140), sub(PRIME, 1), PRIME),

                addmod(/*column18_row1*/ mload(0x3720), sub(PRIME, /*column18_row3*/ mload(0x3760)), PRIME),

                PRIME)



              // Numerator: point - trace_generator^(2 * (trace_length / 2 - 1)).

              // val *= numerators[2].

              val := mulmod(val, mload(0x4ce0), PRIME)

              // Denominator: point^(trace_length / 2) - 1.

              // val *= denominator_invs[5].

              val := mulmod(val, mload(0x4780), PRIME)



              // res += val * (coefficients[52] + coefficients[53] * adjustments[6]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[52]*/ mload(0xac0),

                                       mulmod(/*coefficients[53]*/ mload(0xae0),

                                              /*adjustments[6]*/mload(0x4ec0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for public_memory_addr_zero: column17_row2.

              let val := /*column17_row2*/ mload(0x3240)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8) - 1.

              // val *= denominator_invs[7].

              val := mulmod(val, mload(0x47c0), PRIME)



              // res += val * (coefficients[54] + coefficients[55] * adjustments[7]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[54]*/ mload(0xb00),

                                       mulmod(/*coefficients[55]*/ mload(0xb20),

                                              /*adjustments[7]*/mload(0x4ee0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for public_memory_value_zero: column17_row3.

              let val := /*column17_row3*/ mload(0x3260)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8) - 1.

              // val *= denominator_invs[7].

              val := mulmod(val, mload(0x47c0), PRIME)



              // res += val * (coefficients[56] + coefficients[57] * adjustments[7]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[56]*/ mload(0xb40),

                                       mulmod(/*coefficients[57]*/ mload(0xb60),

                                              /*adjustments[7]*/mload(0x4ee0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc16/perm/init0: (rc16/perm/interaction_elm - column19_row2) * column21_inter1_row1 + column19_row0 - rc16/perm/interaction_elm.

              let val := addmod(

                addmod(

                  mulmod(

                    addmod(

                      /*rc16/perm/interaction_elm*/ mload(0x1c0),

                      sub(PRIME, /*column19_row2*/ mload(0x37c0)),

                      PRIME),

                    /*column21_inter1_row1*/ mload(0x3ec0),

                    PRIME),

                  /*column19_row0*/ mload(0x3780),

                  PRIME),

                sub(PRIME, /*rc16/perm/interaction_elm*/ mload(0x1c0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[58] + coefficients[59] * adjustments[5]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[58]*/ mload(0xb80),

                                       mulmod(/*coefficients[59]*/ mload(0xba0),

                                              /*adjustments[5]*/mload(0x4ea0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc16/perm/step0: (rc16/perm/interaction_elm - column19_row6) * column21_inter1_row5 - (rc16/perm/interaction_elm - column19_row4) * column21_inter1_row1.

              let val := addmod(

                mulmod(

                  addmod(

                    /*rc16/perm/interaction_elm*/ mload(0x1c0),

                    sub(PRIME, /*column19_row6*/ mload(0x3840)),

                    PRIME),

                  /*column21_inter1_row5*/ mload(0x3f00),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    addmod(

                      /*rc16/perm/interaction_elm*/ mload(0x1c0),

                      sub(PRIME, /*column19_row4*/ mload(0x3800)),

                      PRIME),

                    /*column21_inter1_row1*/ mload(0x3ec0),

                    PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(4 * (trace_length / 4 - 1)).

              // val *= numerators[3].

              val := mulmod(val, mload(0x4d00), PRIME)

              // Denominator: point^(trace_length / 4) - 1.

              // val *= denominator_invs[8].

              val := mulmod(val, mload(0x47e0), PRIME)



              // res += val * (coefficients[60] + coefficients[61] * adjustments[8]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[60]*/ mload(0xbc0),

                                       mulmod(/*coefficients[61]*/ mload(0xbe0),

                                              /*adjustments[8]*/mload(0x4f00),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc16/perm/last: column21_inter1_row1 - rc16/perm/public_memory_prod.

              let val := addmod(

                /*column21_inter1_row1*/ mload(0x3ec0),

                sub(PRIME, /*rc16/perm/public_memory_prod*/ mload(0x1e0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - trace_generator^(4 * (trace_length / 4 - 1)).

              // val *= denominator_invs[9].

              val := mulmod(val, mload(0x4800), PRIME)



              // res += val * (coefficients[62] + coefficients[63] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[62]*/ mload(0xc00),

                                       mulmod(/*coefficients[63]*/ mload(0xc20),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc16/diff_is_bit: rc16__diff_0 * rc16__diff_0 - rc16__diff_0.

              let val := addmod(

                mulmod(

                  /*intermediate_value/rc16/diff_0*/ mload(0x4160),

                  /*intermediate_value/rc16/diff_0*/ mload(0x4160),

                  PRIME),

                sub(PRIME, /*intermediate_value/rc16/diff_0*/ mload(0x4160)),

                PRIME)



              // Numerator: point - trace_generator^(4 * (trace_length / 4 - 1)).

              // val *= numerators[3].

              val := mulmod(val, mload(0x4d00), PRIME)

              // Denominator: point^(trace_length / 4) - 1.

              // val *= denominator_invs[8].

              val := mulmod(val, mload(0x47e0), PRIME)



              // res += val * (coefficients[64] + coefficients[65] * adjustments[8]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[64]*/ mload(0xc40),

                                       mulmod(/*coefficients[65]*/ mload(0xc60),

                                              /*adjustments[8]*/mload(0x4f00),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc16/minimum: column19_row2 - rc_min.

              let val := addmod(/*column19_row2*/ mload(0x37c0), sub(PRIME, /*rc_min*/ mload(0x200)), PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[66] + coefficients[67] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[66]*/ mload(0xc80),

                                       mulmod(/*coefficients[67]*/ mload(0xca0),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc16/maximum: column19_row2 - rc_max.

              let val := addmod(/*column19_row2*/ mload(0x37c0), sub(PRIME, /*rc_max*/ mload(0x220)), PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - trace_generator^(4 * (trace_length / 4 - 1)).

              // val *= denominator_invs[9].

              val := mulmod(val, mload(0x4800), PRIME)



              // res += val * (coefficients[68] + coefficients[69] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[68]*/ mload(0xcc0),

                                       mulmod(/*coefficients[69]*/ mload(0xce0),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/ec_subset_sum/booleanity_test: pedersen__hash0__ec_subset_sum__bit_0 * (pedersen__hash0__ec_subset_sum__bit_0 - 1).

              let val := mulmod(

                /*intermediate_value/pedersen/hash0/ec_subset_sum/bit_0*/ mload(0x4180),

                addmod(

                  /*intermediate_value/pedersen/hash0/ec_subset_sum/bit_0*/ mload(0x4180),

                  sub(PRIME, 1),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[70] + coefficients[71] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[70]*/ mload(0xd00),

                                       mulmod(/*coefficients[71]*/ mload(0xd20),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/ec_subset_sum/bit_extraction_end: column4_row0.

              let val := /*column4_row0*/ mload(0x2cc0)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - trace_generator^(63 * trace_length / 64).

              // val *= denominator_invs[10].

              val := mulmod(val, mload(0x4820), PRIME)



              // res += val * (coefficients[72] + coefficients[73] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[72]*/ mload(0xd40),

                                       mulmod(/*coefficients[73]*/ mload(0xd60),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/ec_subset_sum/zeros_tail: column4_row0.

              let val := /*column4_row0*/ mload(0x2cc0)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= denominator_invs[11].

              val := mulmod(val, mload(0x4840), PRIME)



              // res += val * (coefficients[74] + coefficients[75] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[74]*/ mload(0xd80),

                                       mulmod(/*coefficients[75]*/ mload(0xda0),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/ec_subset_sum/add_points/slope: pedersen__hash0__ec_subset_sum__bit_0 * (column2_row0 - pedersen__points__y) - column3_row0 * (column1_row0 - pedersen__points__x).

              let val := addmod(

                mulmod(

                  /*intermediate_value/pedersen/hash0/ec_subset_sum/bit_0*/ mload(0x4180),

                  addmod(

                    /*column2_row0*/ mload(0x2c20),

                    sub(PRIME, /*periodic_column/pedersen/points/y*/ mload(0x20)),

                    PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column3_row0*/ mload(0x2ca0),

                    addmod(

                      /*column1_row0*/ mload(0x2b80),

                      sub(PRIME, /*periodic_column/pedersen/points/x*/ mload(0x0)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[76] + coefficients[77] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[76]*/ mload(0xdc0),

                                       mulmod(/*coefficients[77]*/ mload(0xde0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/ec_subset_sum/add_points/x: column3_row0 * column3_row0 - pedersen__hash0__ec_subset_sum__bit_0 * (column1_row0 + pedersen__points__x + column1_row1).

              let val := addmod(

                mulmod(/*column3_row0*/ mload(0x2ca0), /*column3_row0*/ mload(0x2ca0), PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*intermediate_value/pedersen/hash0/ec_subset_sum/bit_0*/ mload(0x4180),

                    addmod(

                      addmod(

                        /*column1_row0*/ mload(0x2b80),

                        /*periodic_column/pedersen/points/x*/ mload(0x0),

                        PRIME),

                      /*column1_row1*/ mload(0x2ba0),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[78] + coefficients[79] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[78]*/ mload(0xe00),

                                       mulmod(/*coefficients[79]*/ mload(0xe20),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/ec_subset_sum/add_points/y: pedersen__hash0__ec_subset_sum__bit_0 * (column2_row0 + column2_row1) - column3_row0 * (column1_row0 - column1_row1).

              let val := addmod(

                mulmod(

                  /*intermediate_value/pedersen/hash0/ec_subset_sum/bit_0*/ mload(0x4180),

                  addmod(/*column2_row0*/ mload(0x2c20), /*column2_row1*/ mload(0x2c40), PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column3_row0*/ mload(0x2ca0),

                    addmod(/*column1_row0*/ mload(0x2b80), sub(PRIME, /*column1_row1*/ mload(0x2ba0)), PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[80] + coefficients[81] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[80]*/ mload(0xe40),

                                       mulmod(/*coefficients[81]*/ mload(0xe60),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/ec_subset_sum/copy_point/x: pedersen__hash0__ec_subset_sum__bit_neg_0 * (column1_row1 - column1_row0).

              let val := mulmod(

                /*intermediate_value/pedersen/hash0/ec_subset_sum/bit_neg_0*/ mload(0x41a0),

                addmod(/*column1_row1*/ mload(0x2ba0), sub(PRIME, /*column1_row0*/ mload(0x2b80)), PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[82] + coefficients[83] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[82]*/ mload(0xe80),

                                       mulmod(/*coefficients[83]*/ mload(0xea0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/ec_subset_sum/copy_point/y: pedersen__hash0__ec_subset_sum__bit_neg_0 * (column2_row1 - column2_row0).

              let val := mulmod(

                /*intermediate_value/pedersen/hash0/ec_subset_sum/bit_neg_0*/ mload(0x41a0),

                addmod(/*column2_row1*/ mload(0x2c40), sub(PRIME, /*column2_row0*/ mload(0x2c20)), PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[84] + coefficients[85] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[84]*/ mload(0xec0),

                                       mulmod(/*coefficients[85]*/ mload(0xee0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/copy_point/x: column1_row256 - column1_row255.

              let val := addmod(

                /*column1_row256*/ mload(0x2be0),

                sub(PRIME, /*column1_row255*/ mload(0x2bc0)),

                PRIME)



              // Numerator: point^(trace_length / 512) - trace_generator^(trace_length / 2).

              // val *= numerators[5].

              val := mulmod(val, mload(0x4d40), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[86] + coefficients[87] * adjustments[11]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[86]*/ mload(0xf00),

                                       mulmod(/*coefficients[87]*/ mload(0xf20),

                                              /*adjustments[11]*/mload(0x4f60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/copy_point/y: column2_row256 - column2_row255.

              let val := addmod(

                /*column2_row256*/ mload(0x2c80),

                sub(PRIME, /*column2_row255*/ mload(0x2c60)),

                PRIME)



              // Numerator: point^(trace_length / 512) - trace_generator^(trace_length / 2).

              // val *= numerators[5].

              val := mulmod(val, mload(0x4d40), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[88] + coefficients[89] * adjustments[11]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[88]*/ mload(0xf40),

                                       mulmod(/*coefficients[89]*/ mload(0xf60),

                                              /*adjustments[11]*/mload(0x4f60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/init/x: column1_row0 - pedersen/shift_point.x.

              let val := addmod(

                /*column1_row0*/ mload(0x2b80),

                sub(PRIME, /*pedersen/shift_point.x*/ mload(0x240)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[90] + coefficients[91] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[90]*/ mload(0xf80),

                                       mulmod(/*coefficients[91]*/ mload(0xfa0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash0/init/y: column2_row0 - pedersen/shift_point.y.

              let val := addmod(

                /*column2_row0*/ mload(0x2c20),

                sub(PRIME, /*pedersen/shift_point.y*/ mload(0x260)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[92] + coefficients[93] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[92]*/ mload(0xfc0),

                                       mulmod(/*coefficients[93]*/ mload(0xfe0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/ec_subset_sum/booleanity_test: pedersen__hash1__ec_subset_sum__bit_0 * (pedersen__hash1__ec_subset_sum__bit_0 - 1).

              let val := mulmod(

                /*intermediate_value/pedersen/hash1/ec_subset_sum/bit_0*/ mload(0x41c0),

                addmod(

                  /*intermediate_value/pedersen/hash1/ec_subset_sum/bit_0*/ mload(0x41c0),

                  sub(PRIME, 1),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[94] + coefficients[95] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[94]*/ mload(0x1000),

                                       mulmod(/*coefficients[95]*/ mload(0x1020),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/ec_subset_sum/bit_extraction_end: column8_row0.

              let val := /*column8_row0*/ mload(0x2e60)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - trace_generator^(63 * trace_length / 64).

              // val *= denominator_invs[10].

              val := mulmod(val, mload(0x4820), PRIME)



              // res += val * (coefficients[96] + coefficients[97] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[96]*/ mload(0x1040),

                                       mulmod(/*coefficients[97]*/ mload(0x1060),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/ec_subset_sum/zeros_tail: column8_row0.

              let val := /*column8_row0*/ mload(0x2e60)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= denominator_invs[11].

              val := mulmod(val, mload(0x4840), PRIME)



              // res += val * (coefficients[98] + coefficients[99] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[98]*/ mload(0x1080),

                                       mulmod(/*coefficients[99]*/ mload(0x10a0),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/ec_subset_sum/add_points/slope: pedersen__hash1__ec_subset_sum__bit_0 * (column6_row0 - pedersen__points__y) - column7_row0 * (column5_row0 - pedersen__points__x).

              let val := addmod(

                mulmod(

                  /*intermediate_value/pedersen/hash1/ec_subset_sum/bit_0*/ mload(0x41c0),

                  addmod(

                    /*column6_row0*/ mload(0x2dc0),

                    sub(PRIME, /*periodic_column/pedersen/points/y*/ mload(0x20)),

                    PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column7_row0*/ mload(0x2e40),

                    addmod(

                      /*column5_row0*/ mload(0x2d20),

                      sub(PRIME, /*periodic_column/pedersen/points/x*/ mload(0x0)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[100] + coefficients[101] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[100]*/ mload(0x10c0),

                                       mulmod(/*coefficients[101]*/ mload(0x10e0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/ec_subset_sum/add_points/x: column7_row0 * column7_row0 - pedersen__hash1__ec_subset_sum__bit_0 * (column5_row0 + pedersen__points__x + column5_row1).

              let val := addmod(

                mulmod(/*column7_row0*/ mload(0x2e40), /*column7_row0*/ mload(0x2e40), PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*intermediate_value/pedersen/hash1/ec_subset_sum/bit_0*/ mload(0x41c0),

                    addmod(

                      addmod(

                        /*column5_row0*/ mload(0x2d20),

                        /*periodic_column/pedersen/points/x*/ mload(0x0),

                        PRIME),

                      /*column5_row1*/ mload(0x2d40),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[102] + coefficients[103] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[102]*/ mload(0x1100),

                                       mulmod(/*coefficients[103]*/ mload(0x1120),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/ec_subset_sum/add_points/y: pedersen__hash1__ec_subset_sum__bit_0 * (column6_row0 + column6_row1) - column7_row0 * (column5_row0 - column5_row1).

              let val := addmod(

                mulmod(

                  /*intermediate_value/pedersen/hash1/ec_subset_sum/bit_0*/ mload(0x41c0),

                  addmod(/*column6_row0*/ mload(0x2dc0), /*column6_row1*/ mload(0x2de0), PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column7_row0*/ mload(0x2e40),

                    addmod(/*column5_row0*/ mload(0x2d20), sub(PRIME, /*column5_row1*/ mload(0x2d40)), PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[104] + coefficients[105] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[104]*/ mload(0x1140),

                                       mulmod(/*coefficients[105]*/ mload(0x1160),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/ec_subset_sum/copy_point/x: pedersen__hash1__ec_subset_sum__bit_neg_0 * (column5_row1 - column5_row0).

              let val := mulmod(

                /*intermediate_value/pedersen/hash1/ec_subset_sum/bit_neg_0*/ mload(0x41e0),

                addmod(/*column5_row1*/ mload(0x2d40), sub(PRIME, /*column5_row0*/ mload(0x2d20)), PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[106] + coefficients[107] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[106]*/ mload(0x1180),

                                       mulmod(/*coefficients[107]*/ mload(0x11a0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/ec_subset_sum/copy_point/y: pedersen__hash1__ec_subset_sum__bit_neg_0 * (column6_row1 - column6_row0).

              let val := mulmod(

                /*intermediate_value/pedersen/hash1/ec_subset_sum/bit_neg_0*/ mload(0x41e0),

                addmod(/*column6_row1*/ mload(0x2de0), sub(PRIME, /*column6_row0*/ mload(0x2dc0)), PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[108] + coefficients[109] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[108]*/ mload(0x11c0),

                                       mulmod(/*coefficients[109]*/ mload(0x11e0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/copy_point/x: column5_row256 - column5_row255.

              let val := addmod(

                /*column5_row256*/ mload(0x2d80),

                sub(PRIME, /*column5_row255*/ mload(0x2d60)),

                PRIME)



              // Numerator: point^(trace_length / 512) - trace_generator^(trace_length / 2).

              // val *= numerators[5].

              val := mulmod(val, mload(0x4d40), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[110] + coefficients[111] * adjustments[11]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[110]*/ mload(0x1200),

                                       mulmod(/*coefficients[111]*/ mload(0x1220),

                                              /*adjustments[11]*/mload(0x4f60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/copy_point/y: column6_row256 - column6_row255.

              let val := addmod(

                /*column6_row256*/ mload(0x2e20),

                sub(PRIME, /*column6_row255*/ mload(0x2e00)),

                PRIME)



              // Numerator: point^(trace_length / 512) - trace_generator^(trace_length / 2).

              // val *= numerators[5].

              val := mulmod(val, mload(0x4d40), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[112] + coefficients[113] * adjustments[11]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[112]*/ mload(0x1240),

                                       mulmod(/*coefficients[113]*/ mload(0x1260),

                                              /*adjustments[11]*/mload(0x4f60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/init/x: column5_row0 - pedersen/shift_point.x.

              let val := addmod(

                /*column5_row0*/ mload(0x2d20),

                sub(PRIME, /*pedersen/shift_point.x*/ mload(0x240)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[114] + coefficients[115] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[114]*/ mload(0x1280),

                                       mulmod(/*coefficients[115]*/ mload(0x12a0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash1/init/y: column6_row0 - pedersen/shift_point.y.

              let val := addmod(

                /*column6_row0*/ mload(0x2dc0),

                sub(PRIME, /*pedersen/shift_point.y*/ mload(0x260)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[116] + coefficients[117] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[116]*/ mload(0x12c0),

                                       mulmod(/*coefficients[117]*/ mload(0x12e0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/ec_subset_sum/booleanity_test: pedersen__hash2__ec_subset_sum__bit_0 * (pedersen__hash2__ec_subset_sum__bit_0 - 1).

              let val := mulmod(

                /*intermediate_value/pedersen/hash2/ec_subset_sum/bit_0*/ mload(0x4200),

                addmod(

                  /*intermediate_value/pedersen/hash2/ec_subset_sum/bit_0*/ mload(0x4200),

                  sub(PRIME, 1),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[118] + coefficients[119] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[118]*/ mload(0x1300),

                                       mulmod(/*coefficients[119]*/ mload(0x1320),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/ec_subset_sum/bit_extraction_end: column12_row0.

              let val := /*column12_row0*/ mload(0x3000)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - trace_generator^(63 * trace_length / 64).

              // val *= denominator_invs[10].

              val := mulmod(val, mload(0x4820), PRIME)



              // res += val * (coefficients[120] + coefficients[121] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[120]*/ mload(0x1340),

                                       mulmod(/*coefficients[121]*/ mload(0x1360),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/ec_subset_sum/zeros_tail: column12_row0.

              let val := /*column12_row0*/ mload(0x3000)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= denominator_invs[11].

              val := mulmod(val, mload(0x4840), PRIME)



              // res += val * (coefficients[122] + coefficients[123] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[122]*/ mload(0x1380),

                                       mulmod(/*coefficients[123]*/ mload(0x13a0),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/ec_subset_sum/add_points/slope: pedersen__hash2__ec_subset_sum__bit_0 * (column10_row0 - pedersen__points__y) - column11_row0 * (column9_row0 - pedersen__points__x).

              let val := addmod(

                mulmod(

                  /*intermediate_value/pedersen/hash2/ec_subset_sum/bit_0*/ mload(0x4200),

                  addmod(

                    /*column10_row0*/ mload(0x2f60),

                    sub(PRIME, /*periodic_column/pedersen/points/y*/ mload(0x20)),

                    PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column11_row0*/ mload(0x2fe0),

                    addmod(

                      /*column9_row0*/ mload(0x2ec0),

                      sub(PRIME, /*periodic_column/pedersen/points/x*/ mload(0x0)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[124] + coefficients[125] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[124]*/ mload(0x13c0),

                                       mulmod(/*coefficients[125]*/ mload(0x13e0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/ec_subset_sum/add_points/x: column11_row0 * column11_row0 - pedersen__hash2__ec_subset_sum__bit_0 * (column9_row0 + pedersen__points__x + column9_row1).

              let val := addmod(

                mulmod(/*column11_row0*/ mload(0x2fe0), /*column11_row0*/ mload(0x2fe0), PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*intermediate_value/pedersen/hash2/ec_subset_sum/bit_0*/ mload(0x4200),

                    addmod(

                      addmod(

                        /*column9_row0*/ mload(0x2ec0),

                        /*periodic_column/pedersen/points/x*/ mload(0x0),

                        PRIME),

                      /*column9_row1*/ mload(0x2ee0),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[126] + coefficients[127] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[126]*/ mload(0x1400),

                                       mulmod(/*coefficients[127]*/ mload(0x1420),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/ec_subset_sum/add_points/y: pedersen__hash2__ec_subset_sum__bit_0 * (column10_row0 + column10_row1) - column11_row0 * (column9_row0 - column9_row1).

              let val := addmod(

                mulmod(

                  /*intermediate_value/pedersen/hash2/ec_subset_sum/bit_0*/ mload(0x4200),

                  addmod(/*column10_row0*/ mload(0x2f60), /*column10_row1*/ mload(0x2f80), PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column11_row0*/ mload(0x2fe0),

                    addmod(/*column9_row0*/ mload(0x2ec0), sub(PRIME, /*column9_row1*/ mload(0x2ee0)), PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[128] + coefficients[129] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[128]*/ mload(0x1440),

                                       mulmod(/*coefficients[129]*/ mload(0x1460),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/ec_subset_sum/copy_point/x: pedersen__hash2__ec_subset_sum__bit_neg_0 * (column9_row1 - column9_row0).

              let val := mulmod(

                /*intermediate_value/pedersen/hash2/ec_subset_sum/bit_neg_0*/ mload(0x4220),

                addmod(/*column9_row1*/ mload(0x2ee0), sub(PRIME, /*column9_row0*/ mload(0x2ec0)), PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[130] + coefficients[131] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[130]*/ mload(0x1480),

                                       mulmod(/*coefficients[131]*/ mload(0x14a0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/ec_subset_sum/copy_point/y: pedersen__hash2__ec_subset_sum__bit_neg_0 * (column10_row1 - column10_row0).

              let val := mulmod(

                /*intermediate_value/pedersen/hash2/ec_subset_sum/bit_neg_0*/ mload(0x4220),

                addmod(/*column10_row1*/ mload(0x2f80), sub(PRIME, /*column10_row0*/ mload(0x2f60)), PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[132] + coefficients[133] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[132]*/ mload(0x14c0),

                                       mulmod(/*coefficients[133]*/ mload(0x14e0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/copy_point/x: column9_row256 - column9_row255.

              let val := addmod(

                /*column9_row256*/ mload(0x2f20),

                sub(PRIME, /*column9_row255*/ mload(0x2f00)),

                PRIME)



              // Numerator: point^(trace_length / 512) - trace_generator^(trace_length / 2).

              // val *= numerators[5].

              val := mulmod(val, mload(0x4d40), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[134] + coefficients[135] * adjustments[11]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[134]*/ mload(0x1500),

                                       mulmod(/*coefficients[135]*/ mload(0x1520),

                                              /*adjustments[11]*/mload(0x4f60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/copy_point/y: column10_row256 - column10_row255.

              let val := addmod(

                /*column10_row256*/ mload(0x2fc0),

                sub(PRIME, /*column10_row255*/ mload(0x2fa0)),

                PRIME)



              // Numerator: point^(trace_length / 512) - trace_generator^(trace_length / 2).

              // val *= numerators[5].

              val := mulmod(val, mload(0x4d40), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[136] + coefficients[137] * adjustments[11]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[136]*/ mload(0x1540),

                                       mulmod(/*coefficients[137]*/ mload(0x1560),

                                              /*adjustments[11]*/mload(0x4f60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/init/x: column9_row0 - pedersen/shift_point.x.

              let val := addmod(

                /*column9_row0*/ mload(0x2ec0),

                sub(PRIME, /*pedersen/shift_point.x*/ mload(0x240)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[138] + coefficients[139] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[138]*/ mload(0x1580),

                                       mulmod(/*coefficients[139]*/ mload(0x15a0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash2/init/y: column10_row0 - pedersen/shift_point.y.

              let val := addmod(

                /*column10_row0*/ mload(0x2f60),

                sub(PRIME, /*pedersen/shift_point.y*/ mload(0x260)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[140] + coefficients[141] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[140]*/ mload(0x15c0),

                                       mulmod(/*coefficients[141]*/ mload(0x15e0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/ec_subset_sum/booleanity_test: pedersen__hash3__ec_subset_sum__bit_0 * (pedersen__hash3__ec_subset_sum__bit_0 - 1).

              let val := mulmod(

                /*intermediate_value/pedersen/hash3/ec_subset_sum/bit_0*/ mload(0x4240),

                addmod(

                  /*intermediate_value/pedersen/hash3/ec_subset_sum/bit_0*/ mload(0x4240),

                  sub(PRIME, 1),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[142] + coefficients[143] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[142]*/ mload(0x1600),

                                       mulmod(/*coefficients[143]*/ mload(0x1620),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/ec_subset_sum/bit_extraction_end: column16_row0.

              let val := /*column16_row0*/ mload(0x31a0)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - trace_generator^(63 * trace_length / 64).

              // val *= denominator_invs[10].

              val := mulmod(val, mload(0x4820), PRIME)



              // res += val * (coefficients[144] + coefficients[145] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[144]*/ mload(0x1640),

                                       mulmod(/*coefficients[145]*/ mload(0x1660),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/ec_subset_sum/zeros_tail: column16_row0.

              let val := /*column16_row0*/ mload(0x31a0)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= denominator_invs[11].

              val := mulmod(val, mload(0x4840), PRIME)



              // res += val * (coefficients[146] + coefficients[147] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[146]*/ mload(0x1680),

                                       mulmod(/*coefficients[147]*/ mload(0x16a0),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/ec_subset_sum/add_points/slope: pedersen__hash3__ec_subset_sum__bit_0 * (column14_row0 - pedersen__points__y) - column15_row0 * (column13_row0 - pedersen__points__x).

              let val := addmod(

                mulmod(

                  /*intermediate_value/pedersen/hash3/ec_subset_sum/bit_0*/ mload(0x4240),

                  addmod(

                    /*column14_row0*/ mload(0x3100),

                    sub(PRIME, /*periodic_column/pedersen/points/y*/ mload(0x20)),

                    PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column15_row0*/ mload(0x3180),

                    addmod(

                      /*column13_row0*/ mload(0x3060),

                      sub(PRIME, /*periodic_column/pedersen/points/x*/ mload(0x0)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[148] + coefficients[149] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[148]*/ mload(0x16c0),

                                       mulmod(/*coefficients[149]*/ mload(0x16e0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/ec_subset_sum/add_points/x: column15_row0 * column15_row0 - pedersen__hash3__ec_subset_sum__bit_0 * (column13_row0 + pedersen__points__x + column13_row1).

              let val := addmod(

                mulmod(/*column15_row0*/ mload(0x3180), /*column15_row0*/ mload(0x3180), PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*intermediate_value/pedersen/hash3/ec_subset_sum/bit_0*/ mload(0x4240),

                    addmod(

                      addmod(

                        /*column13_row0*/ mload(0x3060),

                        /*periodic_column/pedersen/points/x*/ mload(0x0),

                        PRIME),

                      /*column13_row1*/ mload(0x3080),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[150] + coefficients[151] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[150]*/ mload(0x1700),

                                       mulmod(/*coefficients[151]*/ mload(0x1720),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/ec_subset_sum/add_points/y: pedersen__hash3__ec_subset_sum__bit_0 * (column14_row0 + column14_row1) - column15_row0 * (column13_row0 - column13_row1).

              let val := addmod(

                mulmod(

                  /*intermediate_value/pedersen/hash3/ec_subset_sum/bit_0*/ mload(0x4240),

                  addmod(/*column14_row0*/ mload(0x3100), /*column14_row1*/ mload(0x3120), PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column15_row0*/ mload(0x3180),

                    addmod(/*column13_row0*/ mload(0x3060), sub(PRIME, /*column13_row1*/ mload(0x3080)), PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[152] + coefficients[153] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[152]*/ mload(0x1740),

                                       mulmod(/*coefficients[153]*/ mload(0x1760),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/ec_subset_sum/copy_point/x: pedersen__hash3__ec_subset_sum__bit_neg_0 * (column13_row1 - column13_row0).

              let val := mulmod(

                /*intermediate_value/pedersen/hash3/ec_subset_sum/bit_neg_0*/ mload(0x4260),

                addmod(/*column13_row1*/ mload(0x3080), sub(PRIME, /*column13_row0*/ mload(0x3060)), PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[154] + coefficients[155] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[154]*/ mload(0x1780),

                                       mulmod(/*coefficients[155]*/ mload(0x17a0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/ec_subset_sum/copy_point/y: pedersen__hash3__ec_subset_sum__bit_neg_0 * (column14_row1 - column14_row0).

              let val := mulmod(

                /*intermediate_value/pedersen/hash3/ec_subset_sum/bit_neg_0*/ mload(0x4260),

                addmod(/*column14_row1*/ mload(0x3120), sub(PRIME, /*column14_row0*/ mload(0x3100)), PRIME),

                PRIME)



              // Numerator: point^(trace_length / 256) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[4].

              val := mulmod(val, mload(0x4d20), PRIME)

              // Denominator: point^trace_length - 1.

              // val *= denominator_invs[0].

              val := mulmod(val, mload(0x46e0), PRIME)



              // res += val * (coefficients[156] + coefficients[157] * adjustments[9]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[156]*/ mload(0x17c0),

                                       mulmod(/*coefficients[157]*/ mload(0x17e0),

                                              /*adjustments[9]*/mload(0x4f20),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/copy_point/x: column13_row256 - column13_row255.

              let val := addmod(

                /*column13_row256*/ mload(0x30c0),

                sub(PRIME, /*column13_row255*/ mload(0x30a0)),

                PRIME)



              // Numerator: point^(trace_length / 512) - trace_generator^(trace_length / 2).

              // val *= numerators[5].

              val := mulmod(val, mload(0x4d40), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[158] + coefficients[159] * adjustments[11]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[158]*/ mload(0x1800),

                                       mulmod(/*coefficients[159]*/ mload(0x1820),

                                              /*adjustments[11]*/mload(0x4f60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/copy_point/y: column14_row256 - column14_row255.

              let val := addmod(

                /*column14_row256*/ mload(0x3160),

                sub(PRIME, /*column14_row255*/ mload(0x3140)),

                PRIME)



              // Numerator: point^(trace_length / 512) - trace_generator^(trace_length / 2).

              // val *= numerators[5].

              val := mulmod(val, mload(0x4d40), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[160] + coefficients[161] * adjustments[11]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[160]*/ mload(0x1840),

                                       mulmod(/*coefficients[161]*/ mload(0x1860),

                                              /*adjustments[11]*/mload(0x4f60),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/init/x: column13_row0 - pedersen/shift_point.x.

              let val := addmod(

                /*column13_row0*/ mload(0x3060),

                sub(PRIME, /*pedersen/shift_point.x*/ mload(0x240)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[162] + coefficients[163] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[162]*/ mload(0x1880),

                                       mulmod(/*coefficients[163]*/ mload(0x18a0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/hash3/init/y: column14_row0 - pedersen/shift_point.y.

              let val := addmod(

                /*column14_row0*/ mload(0x3100),

                sub(PRIME, /*pedersen/shift_point.y*/ mload(0x260)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[164] + coefficients[165] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[164]*/ mload(0x18c0),

                                       mulmod(/*coefficients[165]*/ mload(0x18e0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input0_value0: column17_row7 - column4_row0.

              let val := addmod(/*column17_row7*/ mload(0x32e0), sub(PRIME, /*column4_row0*/ mload(0x2cc0)), PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[166] + coefficients[167] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[166]*/ mload(0x1900),

                                       mulmod(/*coefficients[167]*/ mload(0x1920),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input0_value1: column17_row135 - column8_row0.

              let val := addmod(

                /*column17_row135*/ mload(0x3500),

                sub(PRIME, /*column8_row0*/ mload(0x2e60)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[168] + coefficients[169] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[168]*/ mload(0x1940),

                                       mulmod(/*coefficients[169]*/ mload(0x1960),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input0_value2: column17_row263 - column12_row0.

              let val := addmod(

                /*column17_row263*/ mload(0x35c0),

                sub(PRIME, /*column12_row0*/ mload(0x3000)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[170] + coefficients[171] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[170]*/ mload(0x1980),

                                       mulmod(/*coefficients[171]*/ mload(0x19a0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input0_value3: column17_row391 - column16_row0.

              let val := addmod(

                /*column17_row391*/ mload(0x3620),

                sub(PRIME, /*column16_row0*/ mload(0x31a0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[172] + coefficients[173] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[172]*/ mload(0x19c0),

                                       mulmod(/*coefficients[173]*/ mload(0x19e0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input0_addr: column17_row134 - (column17_row38 + 1).

              let val := addmod(

                /*column17_row134*/ mload(0x34e0),

                sub(PRIME, addmod(/*column17_row38*/ mload(0x33e0), 1, PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(128 * (trace_length / 128 - 1)).

              // val *= numerators[6].

              val := mulmod(val, mload(0x4d60), PRIME)

              // Denominator: point^(trace_length / 128) - 1.

              // val *= denominator_invs[14].

              val := mulmod(val, mload(0x48a0), PRIME)



              // res += val * (coefficients[174] + coefficients[175] * adjustments[13]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[174]*/ mload(0x1a00),

                                       mulmod(/*coefficients[175]*/ mload(0x1a20),

                                              /*adjustments[13]*/mload(0x4fa0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/init_addr: column17_row6 - initial_pedersen_addr.

              let val := addmod(

                /*column17_row6*/ mload(0x32c0),

                sub(PRIME, /*initial_pedersen_addr*/ mload(0x280)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[176] + coefficients[177] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[176]*/ mload(0x1a40),

                                       mulmod(/*coefficients[177]*/ mload(0x1a60),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input1_value0: column17_row71 - column4_row256.

              let val := addmod(

                /*column17_row71*/ mload(0x3440),

                sub(PRIME, /*column4_row256*/ mload(0x2d00)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[178] + coefficients[179] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[178]*/ mload(0x1a80),

                                       mulmod(/*coefficients[179]*/ mload(0x1aa0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input1_value1: column17_row199 - column8_row256.

              let val := addmod(

                /*column17_row199*/ mload(0x3580),

                sub(PRIME, /*column8_row256*/ mload(0x2ea0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[180] + coefficients[181] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[180]*/ mload(0x1ac0),

                                       mulmod(/*coefficients[181]*/ mload(0x1ae0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input1_value2: column17_row327 - column12_row256.

              let val := addmod(

                /*column17_row327*/ mload(0x3600),

                sub(PRIME, /*column12_row256*/ mload(0x3040)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[182] + coefficients[183] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[182]*/ mload(0x1b00),

                                       mulmod(/*coefficients[183]*/ mload(0x1b20),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input1_value3: column17_row455 - column16_row256.

              let val := addmod(

                /*column17_row455*/ mload(0x3680),

                sub(PRIME, /*column16_row256*/ mload(0x31e0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[184] + coefficients[185] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[184]*/ mload(0x1b40),

                                       mulmod(/*coefficients[185]*/ mload(0x1b60),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/input1_addr: column17_row70 - (column17_row6 + 1).

              let val := addmod(

                /*column17_row70*/ mload(0x3420),

                sub(PRIME, addmod(/*column17_row6*/ mload(0x32c0), 1, PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 128) - 1.

              // val *= denominator_invs[14].

              val := mulmod(val, mload(0x48a0), PRIME)



              // res += val * (coefficients[186] + coefficients[187] * adjustments[14]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[186]*/ mload(0x1b80),

                                       mulmod(/*coefficients[187]*/ mload(0x1ba0),

                                              /*adjustments[14]*/mload(0x4fc0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/output_value0: column17_row39 - column1_row511.

              let val := addmod(

                /*column17_row39*/ mload(0x3400),

                sub(PRIME, /*column1_row511*/ mload(0x2c00)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[188] + coefficients[189] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[188]*/ mload(0x1bc0),

                                       mulmod(/*coefficients[189]*/ mload(0x1be0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/output_value1: column17_row167 - column5_row511.

              let val := addmod(

                /*column17_row167*/ mload(0x3560),

                sub(PRIME, /*column5_row511*/ mload(0x2da0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[190] + coefficients[191] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[190]*/ mload(0x1c00),

                                       mulmod(/*coefficients[191]*/ mload(0x1c20),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/output_value2: column17_row295 - column9_row511.

              let val := addmod(

                /*column17_row295*/ mload(0x35e0),

                sub(PRIME, /*column9_row511*/ mload(0x2f40)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[192] + coefficients[193] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[192]*/ mload(0x1c40),

                                       mulmod(/*coefficients[193]*/ mload(0x1c60),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/output_value3: column17_row423 - column13_row511.

              let val := addmod(

                /*column17_row423*/ mload(0x3660),

                sub(PRIME, /*column13_row511*/ mload(0x30e0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 512) - 1.

              // val *= denominator_invs[13].

              val := mulmod(val, mload(0x4880), PRIME)



              // res += val * (coefficients[194] + coefficients[195] * adjustments[12]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[194]*/ mload(0x1c80),

                                       mulmod(/*coefficients[195]*/ mload(0x1ca0),

                                              /*adjustments[12]*/mload(0x4f80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for pedersen/output_addr: column17_row38 - (column17_row70 + 1).

              let val := addmod(

                /*column17_row38*/ mload(0x33e0),

                sub(PRIME, addmod(/*column17_row70*/ mload(0x3420), 1, PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 128) - 1.

              // val *= denominator_invs[14].

              val := mulmod(val, mload(0x48a0), PRIME)



              // res += val * (coefficients[196] + coefficients[197] * adjustments[14]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[196]*/ mload(0x1cc0),

                                       mulmod(/*coefficients[197]*/ mload(0x1ce0),

                                              /*adjustments[14]*/mload(0x4fc0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc_builtin/value: rc_builtin__value7_0 - column17_row103.

              let val := addmod(

                /*intermediate_value/rc_builtin/value7_0*/ mload(0x4360),

                sub(PRIME, /*column17_row103*/ mload(0x34c0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 128) - 1.

              // val *= denominator_invs[14].

              val := mulmod(val, mload(0x48a0), PRIME)



              // res += val * (coefficients[198] + coefficients[199] * adjustments[14]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[198]*/ mload(0x1d00),

                                       mulmod(/*coefficients[199]*/ mload(0x1d20),

                                              /*adjustments[14]*/mload(0x4fc0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc_builtin/addr_step: column17_row230 - (column17_row102 + 1).

              let val := addmod(

                /*column17_row230*/ mload(0x35a0),

                sub(PRIME, addmod(/*column17_row102*/ mload(0x34a0), 1, PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(128 * (trace_length / 128 - 1)).

              // val *= numerators[6].

              val := mulmod(val, mload(0x4d60), PRIME)

              // Denominator: point^(trace_length / 128) - 1.

              // val *= denominator_invs[14].

              val := mulmod(val, mload(0x48a0), PRIME)



              // res += val * (coefficients[200] + coefficients[201] * adjustments[13]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[200]*/ mload(0x1d40),

                                       mulmod(/*coefficients[201]*/ mload(0x1d60),

                                              /*adjustments[13]*/mload(0x4fa0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for rc_builtin/init_addr: column17_row102 - initial_rc_addr.

              let val := addmod(

                /*column17_row102*/ mload(0x34a0),

                sub(PRIME, /*initial_rc_addr*/ mload(0x2a0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[202] + coefficients[203] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[202]*/ mload(0x1d80),

                                       mulmod(/*coefficients[203]*/ mload(0x1da0),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/doubling_key/slope: ecdsa__signature0__doubling_key__x_squared + ecdsa__signature0__doubling_key__x_squared + ecdsa__signature0__doubling_key__x_squared + ecdsa/sig_config.alpha - (column19_row15 + column19_row15) * column20_row0.

              let val := addmod(

                addmod(

                  addmod(

                    addmod(

                      /*intermediate_value/ecdsa/signature0/doubling_key/x_squared*/ mload(0x4380),

                      /*intermediate_value/ecdsa/signature0/doubling_key/x_squared*/ mload(0x4380),

                      PRIME),

                    /*intermediate_value/ecdsa/signature0/doubling_key/x_squared*/ mload(0x4380),

                    PRIME),

                  /*ecdsa/sig_config.alpha*/ mload(0x2c0),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    addmod(/*column19_row15*/ mload(0x3920), /*column19_row15*/ mload(0x3920), PRIME),

                    /*column20_row0*/ mload(0x3ae0),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[204] + coefficients[205] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[204]*/ mload(0x1dc0),

                                       mulmod(/*coefficients[205]*/ mload(0x1de0),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/doubling_key/x: column20_row0 * column20_row0 - (column19_row7 + column19_row7 + column19_row23).

              let val := addmod(

                mulmod(/*column20_row0*/ mload(0x3ae0), /*column20_row0*/ mload(0x3ae0), PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(/*column19_row7*/ mload(0x3860), /*column19_row7*/ mload(0x3860), PRIME),

                    /*column19_row23*/ mload(0x3960),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[206] + coefficients[207] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[206]*/ mload(0x1e00),

                                       mulmod(/*coefficients[207]*/ mload(0x1e20),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/doubling_key/y: column19_row15 + column19_row31 - column20_row0 * (column19_row7 - column19_row23).

              let val := addmod(

                addmod(/*column19_row15*/ mload(0x3920), /*column19_row31*/ mload(0x39c0), PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column20_row0*/ mload(0x3ae0),

                    addmod(

                      /*column19_row7*/ mload(0x3860),

                      sub(PRIME, /*column19_row23*/ mload(0x3960)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[208] + coefficients[209] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[208]*/ mload(0x1e40),

                                       mulmod(/*coefficients[209]*/ mload(0x1e60),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/booleanity_test: ecdsa__signature0__exponentiate_generator__bit_0 * (ecdsa__signature0__exponentiate_generator__bit_0 - 1).

              let val := mulmod(

                /*intermediate_value/ecdsa/signature0/exponentiate_generator/bit_0*/ mload(0x43a0),

                addmod(

                  /*intermediate_value/ecdsa/signature0/exponentiate_generator/bit_0*/ mload(0x43a0),

                  sub(PRIME, 1),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[8].

              val := mulmod(val, mload(0x4da0), PRIME)

              // Denominator: point^(trace_length / 32) - 1.

              // val *= denominator_invs[15].

              val := mulmod(val, mload(0x48c0), PRIME)



              // res += val * (coefficients[210] + coefficients[211] * adjustments[16]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[210]*/ mload(0x1e80),

                                       mulmod(/*coefficients[211]*/ mload(0x1ea0),

                                              /*adjustments[16]*/mload(0x5000),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/bit_extraction_end: column20_row30.

              let val := /*column20_row30*/ mload(0x3c80)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - trace_generator^(251 * trace_length / 256).

              // val *= denominator_invs[16].

              val := mulmod(val, mload(0x48e0), PRIME)



              // res += val * (coefficients[212] + coefficients[213] * adjustments[17]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[212]*/ mload(0x1ec0),

                                       mulmod(/*coefficients[213]*/ mload(0x1ee0),

                                              /*adjustments[17]*/mload(0x5020),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/zeros_tail: column20_row30.

              let val := /*column20_row30*/ mload(0x3c80)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              // val *= denominator_invs[17].

              val := mulmod(val, mload(0x4900), PRIME)



              // res += val * (coefficients[214] + coefficients[215] * adjustments[17]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[214]*/ mload(0x1f00),

                                       mulmod(/*coefficients[215]*/ mload(0x1f20),

                                              /*adjustments[17]*/mload(0x5020),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/slope: ecdsa__signature0__exponentiate_generator__bit_0 * (column20_row22 - ecdsa__generator_points__y) - column20_row14 * (column20_row6 - ecdsa__generator_points__x).

              let val := addmod(

                mulmod(

                  /*intermediate_value/ecdsa/signature0/exponentiate_generator/bit_0*/ mload(0x43a0),

                  addmod(

                    /*column20_row22*/ mload(0x3c40),

                    sub(PRIME, /*periodic_column/ecdsa/generator_points/y*/ mload(0x60)),

                    PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column20_row14*/ mload(0x3be0),

                    addmod(

                      /*column20_row6*/ mload(0x3b60),

                      sub(PRIME, /*periodic_column/ecdsa/generator_points/x*/ mload(0x40)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[8].

              val := mulmod(val, mload(0x4da0), PRIME)

              // Denominator: point^(trace_length / 32) - 1.

              // val *= denominator_invs[15].

              val := mulmod(val, mload(0x48c0), PRIME)



              // res += val * (coefficients[216] + coefficients[217] * adjustments[16]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[216]*/ mload(0x1f40),

                                       mulmod(/*coefficients[217]*/ mload(0x1f60),

                                              /*adjustments[16]*/mload(0x5000),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/x: column20_row14 * column20_row14 - ecdsa__signature0__exponentiate_generator__bit_0 * (column20_row6 + ecdsa__generator_points__x + column20_row38).

              let val := addmod(

                mulmod(/*column20_row14*/ mload(0x3be0), /*column20_row14*/ mload(0x3be0), PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*intermediate_value/ecdsa/signature0/exponentiate_generator/bit_0*/ mload(0x43a0),

                    addmod(

                      addmod(

                        /*column20_row6*/ mload(0x3b60),

                        /*periodic_column/ecdsa/generator_points/x*/ mload(0x40),

                        PRIME),

                      /*column20_row38*/ mload(0x3ca0),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[8].

              val := mulmod(val, mload(0x4da0), PRIME)

              // Denominator: point^(trace_length / 32) - 1.

              // val *= denominator_invs[15].

              val := mulmod(val, mload(0x48c0), PRIME)



              // res += val * (coefficients[218] + coefficients[219] * adjustments[16]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[218]*/ mload(0x1f80),

                                       mulmod(/*coefficients[219]*/ mload(0x1fa0),

                                              /*adjustments[16]*/mload(0x5000),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/y: ecdsa__signature0__exponentiate_generator__bit_0 * (column20_row22 + column20_row54) - column20_row14 * (column20_row6 - column20_row38).

              let val := addmod(

                mulmod(

                  /*intermediate_value/ecdsa/signature0/exponentiate_generator/bit_0*/ mload(0x43a0),

                  addmod(/*column20_row22*/ mload(0x3c40), /*column20_row54*/ mload(0x3cc0), PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column20_row14*/ mload(0x3be0),

                    addmod(

                      /*column20_row6*/ mload(0x3b60),

                      sub(PRIME, /*column20_row38*/ mload(0x3ca0)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[8].

              val := mulmod(val, mload(0x4da0), PRIME)

              // Denominator: point^(trace_length / 32) - 1.

              // val *= denominator_invs[15].

              val := mulmod(val, mload(0x48c0), PRIME)



              // res += val * (coefficients[220] + coefficients[221] * adjustments[16]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[220]*/ mload(0x1fc0),

                                       mulmod(/*coefficients[221]*/ mload(0x1fe0),

                                              /*adjustments[16]*/mload(0x5000),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/x_diff_inv: column20_row1 * (column20_row6 - ecdsa__generator_points__x) - 1.

              let val := addmod(

                mulmod(

                  /*column20_row1*/ mload(0x3b00),

                  addmod(

                    /*column20_row6*/ mload(0x3b60),

                    sub(PRIME, /*periodic_column/ecdsa/generator_points/x*/ mload(0x40)),

                    PRIME),

                  PRIME),

                sub(PRIME, 1),

                PRIME)



              // Numerator: point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[8].

              val := mulmod(val, mload(0x4da0), PRIME)

              // Denominator: point^(trace_length / 32) - 1.

              // val *= denominator_invs[15].

              val := mulmod(val, mload(0x48c0), PRIME)



              // res += val * (coefficients[222] + coefficients[223] * adjustments[16]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[222]*/ mload(0x2000),

                                       mulmod(/*coefficients[223]*/ mload(0x2020),

                                              /*adjustments[16]*/mload(0x5000),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/copy_point/x: ecdsa__signature0__exponentiate_generator__bit_neg_0 * (column20_row38 - column20_row6).

              let val := mulmod(

                /*intermediate_value/ecdsa/signature0/exponentiate_generator/bit_neg_0*/ mload(0x43c0),

                addmod(

                  /*column20_row38*/ mload(0x3ca0),

                  sub(PRIME, /*column20_row6*/ mload(0x3b60)),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[8].

              val := mulmod(val, mload(0x4da0), PRIME)

              // Denominator: point^(trace_length / 32) - 1.

              // val *= denominator_invs[15].

              val := mulmod(val, mload(0x48c0), PRIME)



              // res += val * (coefficients[224] + coefficients[225] * adjustments[16]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[224]*/ mload(0x2040),

                                       mulmod(/*coefficients[225]*/ mload(0x2060),

                                              /*adjustments[16]*/mload(0x5000),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_generator/copy_point/y: ecdsa__signature0__exponentiate_generator__bit_neg_0 * (column20_row54 - column20_row22).

              let val := mulmod(

                /*intermediate_value/ecdsa/signature0/exponentiate_generator/bit_neg_0*/ mload(0x43c0),

                addmod(

                  /*column20_row54*/ mload(0x3cc0),

                  sub(PRIME, /*column20_row22*/ mload(0x3c40)),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 8192) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[8].

              val := mulmod(val, mload(0x4da0), PRIME)

              // Denominator: point^(trace_length / 32) - 1.

              // val *= denominator_invs[15].

              val := mulmod(val, mload(0x48c0), PRIME)



              // res += val * (coefficients[226] + coefficients[227] * adjustments[16]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[226]*/ mload(0x2080),

                                       mulmod(/*coefficients[227]*/ mload(0x20a0),

                                              /*adjustments[16]*/mload(0x5000),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/booleanity_test: ecdsa__signature0__exponentiate_key__bit_0 * (ecdsa__signature0__exponentiate_key__bit_0 - 1).

              let val := mulmod(

                /*intermediate_value/ecdsa/signature0/exponentiate_key/bit_0*/ mload(0x43e0),

                addmod(

                  /*intermediate_value/ecdsa/signature0/exponentiate_key/bit_0*/ mload(0x43e0),

                  sub(PRIME, 1),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[228] + coefficients[229] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[228]*/ mload(0x20c0),

                                       mulmod(/*coefficients[229]*/ mload(0x20e0),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/bit_extraction_end: column20_row2.

              let val := /*column20_row2*/ mload(0x3b20)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 4096) - trace_generator^(251 * trace_length / 256).

              // val *= denominator_invs[18].

              val := mulmod(val, mload(0x4920), PRIME)



              // res += val * (coefficients[230] + coefficients[231] * adjustments[18]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[230]*/ mload(0x2100),

                                       mulmod(/*coefficients[231]*/ mload(0x2120),

                                              /*adjustments[18]*/mload(0x5040),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/zeros_tail: column20_row2.

              let val := /*column20_row2*/ mload(0x3b20)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= denominator_invs[19].

              val := mulmod(val, mload(0x4940), PRIME)



              // res += val * (coefficients[232] + coefficients[233] * adjustments[18]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[232]*/ mload(0x2140),

                                       mulmod(/*coefficients[233]*/ mload(0x2160),

                                              /*adjustments[18]*/mload(0x5040),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/add_points/slope: ecdsa__signature0__exponentiate_key__bit_0 * (column20_row4 - column19_row15) - column20_row12 * (column20_row8 - column19_row7).

              let val := addmod(

                mulmod(

                  /*intermediate_value/ecdsa/signature0/exponentiate_key/bit_0*/ mload(0x43e0),

                  addmod(

                    /*column20_row4*/ mload(0x3b40),

                    sub(PRIME, /*column19_row15*/ mload(0x3920)),

                    PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column20_row12*/ mload(0x3bc0),

                    addmod(/*column20_row8*/ mload(0x3b80), sub(PRIME, /*column19_row7*/ mload(0x3860)), PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[234] + coefficients[235] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[234]*/ mload(0x2180),

                                       mulmod(/*coefficients[235]*/ mload(0x21a0),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/add_points/x: column20_row12 * column20_row12 - ecdsa__signature0__exponentiate_key__bit_0 * (column20_row8 + column19_row7 + column20_row24).

              let val := addmod(

                mulmod(/*column20_row12*/ mload(0x3bc0), /*column20_row12*/ mload(0x3bc0), PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*intermediate_value/ecdsa/signature0/exponentiate_key/bit_0*/ mload(0x43e0),

                    addmod(

                      addmod(/*column20_row8*/ mload(0x3b80), /*column19_row7*/ mload(0x3860), PRIME),

                      /*column20_row24*/ mload(0x3c60),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[236] + coefficients[237] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[236]*/ mload(0x21c0),

                                       mulmod(/*coefficients[237]*/ mload(0x21e0),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/add_points/y: ecdsa__signature0__exponentiate_key__bit_0 * (column20_row4 + column20_row20) - column20_row12 * (column20_row8 - column20_row24).

              let val := addmod(

                mulmod(

                  /*intermediate_value/ecdsa/signature0/exponentiate_key/bit_0*/ mload(0x43e0),

                  addmod(/*column20_row4*/ mload(0x3b40), /*column20_row20*/ mload(0x3c20), PRIME),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column20_row12*/ mload(0x3bc0),

                    addmod(

                      /*column20_row8*/ mload(0x3b80),

                      sub(PRIME, /*column20_row24*/ mload(0x3c60)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[238] + coefficients[239] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[238]*/ mload(0x2200),

                                       mulmod(/*coefficients[239]*/ mload(0x2220),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/add_points/x_diff_inv: column20_row10 * (column20_row8 - column19_row7) - 1.

              let val := addmod(

                mulmod(

                  /*column20_row10*/ mload(0x3ba0),

                  addmod(/*column20_row8*/ mload(0x3b80), sub(PRIME, /*column19_row7*/ mload(0x3860)), PRIME),

                  PRIME),

                sub(PRIME, 1),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[240] + coefficients[241] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[240]*/ mload(0x2240),

                                       mulmod(/*coefficients[241]*/ mload(0x2260),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/copy_point/x: ecdsa__signature0__exponentiate_key__bit_neg_0 * (column20_row24 - column20_row8).

              let val := mulmod(

                /*intermediate_value/ecdsa/signature0/exponentiate_key/bit_neg_0*/ mload(0x4400),

                addmod(

                  /*column20_row24*/ mload(0x3c60),

                  sub(PRIME, /*column20_row8*/ mload(0x3b80)),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[242] + coefficients[243] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[242]*/ mload(0x2280),

                                       mulmod(/*coefficients[243]*/ mload(0x22a0),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/exponentiate_key/copy_point/y: ecdsa__signature0__exponentiate_key__bit_neg_0 * (column20_row20 - column20_row4).

              let val := mulmod(

                /*intermediate_value/ecdsa/signature0/exponentiate_key/bit_neg_0*/ mload(0x4400),

                addmod(

                  /*column20_row20*/ mload(0x3c20),

                  sub(PRIME, /*column20_row4*/ mload(0x3b40)),

                  PRIME),

                PRIME)



              // Numerator: point^(trace_length / 4096) - trace_generator^(255 * trace_length / 256).

              // val *= numerators[7].

              val := mulmod(val, mload(0x4d80), PRIME)

              // Denominator: point^(trace_length / 16) - 1.

              // val *= denominator_invs[2].

              val := mulmod(val, mload(0x4720), PRIME)



              // res += val * (coefficients[244] + coefficients[245] * adjustments[15]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[244]*/ mload(0x22c0),

                                       mulmod(/*coefficients[245]*/ mload(0x22e0),

                                              /*adjustments[15]*/mload(0x4fe0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/init_gen/x: column20_row6 - ecdsa/sig_config.shift_point.x.

              let val := addmod(

                /*column20_row6*/ mload(0x3b60),

                sub(PRIME, /*ecdsa/sig_config.shift_point.x*/ mload(0x2e0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[246] + coefficients[247] * adjustments[17]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[246]*/ mload(0x2300),

                                       mulmod(/*coefficients[247]*/ mload(0x2320),

                                              /*adjustments[17]*/mload(0x5020),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/init_gen/y: column20_row22 + ecdsa/sig_config.shift_point.y.

              let val := addmod(

                /*column20_row22*/ mload(0x3c40),

                /*ecdsa/sig_config.shift_point.y*/ mload(0x300),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[248] + coefficients[249] * adjustments[17]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[248]*/ mload(0x2340),

                                       mulmod(/*coefficients[249]*/ mload(0x2360),

                                              /*adjustments[17]*/mload(0x5020),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/init_key/x: column20_row8 - ecdsa/sig_config.shift_point.x.

              let val := addmod(

                /*column20_row8*/ mload(0x3b80),

                sub(PRIME, /*ecdsa/sig_config.shift_point.x*/ mload(0x2e0)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 4096) - 1.

              // val *= denominator_invs[21].

              val := mulmod(val, mload(0x4980), PRIME)



              // res += val * (coefficients[250] + coefficients[251] * adjustments[18]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[250]*/ mload(0x2380),

                                       mulmod(/*coefficients[251]*/ mload(0x23a0),

                                              /*adjustments[18]*/mload(0x5040),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/init_key/y: column20_row4 - ecdsa/sig_config.shift_point.y.

              let val := addmod(

                /*column20_row4*/ mload(0x3b40),

                sub(PRIME, /*ecdsa/sig_config.shift_point.y*/ mload(0x300)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 4096) - 1.

              // val *= denominator_invs[21].

              val := mulmod(val, mload(0x4980), PRIME)



              // res += val * (coefficients[252] + coefficients[253] * adjustments[18]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[252]*/ mload(0x23c0),

                                       mulmod(/*coefficients[253]*/ mload(0x23e0),

                                              /*adjustments[18]*/mload(0x5040),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/add_results/slope: column20_row8182 - (column20_row4084 + column20_row8161 * (column20_row8166 - column20_row4088)).

              let val := addmod(

                /*column20_row8182*/ mload(0x3e40),

                sub(

                  PRIME,

                  addmod(

                    /*column20_row4084*/ mload(0x3d20),

                    mulmod(

                      /*column20_row8161*/ mload(0x3da0),

                      addmod(

                        /*column20_row8166*/ mload(0x3dc0),

                        sub(PRIME, /*column20_row4088*/ mload(0x3d40)),

                        PRIME),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[254] + coefficients[255] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[254]*/ mload(0x2400),

                                       mulmod(/*coefficients[255]*/ mload(0x2420),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/add_results/x: column20_row8161 * column20_row8161 - (column20_row8166 + column20_row4088 + column19_row4103).

              let val := addmod(

                mulmod(/*column20_row8161*/ mload(0x3da0), /*column20_row8161*/ mload(0x3da0), PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(/*column20_row8166*/ mload(0x3dc0), /*column20_row4088*/ mload(0x3d40), PRIME),

                    /*column19_row4103*/ mload(0x3aa0),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[256] + coefficients[257] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[256]*/ mload(0x2440),

                                       mulmod(/*coefficients[257]*/ mload(0x2460),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/add_results/y: column20_row8182 + column19_row4111 - column20_row8161 * (column20_row8166 - column19_row4103).

              let val := addmod(

                addmod(/*column20_row8182*/ mload(0x3e40), /*column19_row4111*/ mload(0x3ac0), PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column20_row8161*/ mload(0x3da0),

                    addmod(

                      /*column20_row8166*/ mload(0x3dc0),

                      sub(PRIME, /*column19_row4103*/ mload(0x3aa0)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[258] + coefficients[259] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[258]*/ mload(0x2480),

                                       mulmod(/*coefficients[259]*/ mload(0x24a0),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/add_results/x_diff_inv: column20_row8174 * (column20_row8166 - column20_row4088) - 1.

              let val := addmod(

                mulmod(

                  /*column20_row8174*/ mload(0x3de0),

                  addmod(

                    /*column20_row8166*/ mload(0x3dc0),

                    sub(PRIME, /*column20_row4088*/ mload(0x3d40)),

                    PRIME),

                  PRIME),

                sub(PRIME, 1),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[260] + coefficients[261] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[260]*/ mload(0x24c0),

                                       mulmod(/*coefficients[261]*/ mload(0x24e0),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/extract_r/slope: column20_row8180 + ecdsa/sig_config.shift_point.y - column20_row4092 * (column20_row8184 - ecdsa/sig_config.shift_point.x).

              let val := addmod(

                addmod(

                  /*column20_row8180*/ mload(0x3e20),

                  /*ecdsa/sig_config.shift_point.y*/ mload(0x300),

                  PRIME),

                sub(

                  PRIME,

                  mulmod(

                    /*column20_row4092*/ mload(0x3d80),

                    addmod(

                      /*column20_row8184*/ mload(0x3e60),

                      sub(PRIME, /*ecdsa/sig_config.shift_point.x*/ mload(0x2e0)),

                      PRIME),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[262] + coefficients[263] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[262]*/ mload(0x2500),

                                       mulmod(/*coefficients[263]*/ mload(0x2520),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/extract_r/x: column20_row4092 * column20_row4092 - (column20_row8184 + ecdsa/sig_config.shift_point.x + column20_row2).

              let val := addmod(

                mulmod(/*column20_row4092*/ mload(0x3d80), /*column20_row4092*/ mload(0x3d80), PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      /*column20_row8184*/ mload(0x3e60),

                      /*ecdsa/sig_config.shift_point.x*/ mload(0x2e0),

                      PRIME),

                    /*column20_row2*/ mload(0x3b20),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[264] + coefficients[265] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[264]*/ mload(0x2540),

                                       mulmod(/*coefficients[265]*/ mload(0x2560),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/extract_r/x_diff_inv: column20_row8188 * (column20_row8184 - ecdsa/sig_config.shift_point.x) - 1.

              let val := addmod(

                mulmod(

                  /*column20_row8188*/ mload(0x3e80),

                  addmod(

                    /*column20_row8184*/ mload(0x3e60),

                    sub(PRIME, /*ecdsa/sig_config.shift_point.x*/ mload(0x2e0)),

                    PRIME),

                  PRIME),

                sub(PRIME, 1),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[266] + coefficients[267] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[266]*/ mload(0x2580),

                                       mulmod(/*coefficients[267]*/ mload(0x25a0),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/z_nonzero: column20_row30 * column20_row4080 - 1.

              let val := addmod(

                mulmod(/*column20_row30*/ mload(0x3c80), /*column20_row4080*/ mload(0x3d00), PRIME),

                sub(PRIME, 1),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[268] + coefficients[269] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[268]*/ mload(0x25c0),

                                       mulmod(/*coefficients[269]*/ mload(0x25e0),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/r_and_w_nonzero: column20_row2 * column20_row4090 - 1.

              let val := addmod(

                mulmod(/*column20_row2*/ mload(0x3b20), /*column20_row4090*/ mload(0x3d60), PRIME),

                sub(PRIME, 1),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 4096) - 1.

              // val *= denominator_invs[21].

              val := mulmod(val, mload(0x4980), PRIME)



              // res += val * (coefficients[270] + coefficients[271] * adjustments[20]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[270]*/ mload(0x2600),

                                       mulmod(/*coefficients[271]*/ mload(0x2620),

                                              /*adjustments[20]*/mload(0x5080),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/q_on_curve/x_squared: column20_row8176 - column19_row7 * column19_row7.

              let val := addmod(

                /*column20_row8176*/ mload(0x3e00),

                sub(

                  PRIME,

                  mulmod(/*column19_row7*/ mload(0x3860), /*column19_row7*/ mload(0x3860), PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[272] + coefficients[273] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[272]*/ mload(0x2640),

                                       mulmod(/*coefficients[273]*/ mload(0x2660),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/signature0/q_on_curve/on_curve: column19_row15 * column19_row15 - (column19_row7 * column20_row8176 + ecdsa/sig_config.alpha * column19_row7 + ecdsa/sig_config.beta).

              let val := addmod(

                mulmod(/*column19_row15*/ mload(0x3920), /*column19_row15*/ mload(0x3920), PRIME),

                sub(

                  PRIME,

                  addmod(

                    addmod(

                      mulmod(/*column19_row7*/ mload(0x3860), /*column20_row8176*/ mload(0x3e00), PRIME),

                      mulmod(/*ecdsa/sig_config.alpha*/ mload(0x2c0), /*column19_row7*/ mload(0x3860), PRIME),

                      PRIME),

                    /*ecdsa/sig_config.beta*/ mload(0x320),

                    PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[274] + coefficients[275] * adjustments[19]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[274]*/ mload(0x2680),

                                       mulmod(/*coefficients[275]*/ mload(0x26a0),

                                              /*adjustments[19]*/mload(0x5060),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/init_addr: column17_row22 - initial_ecdsa_addr.

              let val := addmod(

                /*column17_row22*/ mload(0x33a0),

                sub(PRIME, /*initial_ecdsa_addr*/ mload(0x340)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[276] + coefficients[277] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[276]*/ mload(0x26c0),

                                       mulmod(/*coefficients[277]*/ mload(0x26e0),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/message_addr: column17_row4118 - (column17_row22 + 1).

              let val := addmod(

                /*column17_row4118*/ mload(0x36a0),

                sub(PRIME, addmod(/*column17_row22*/ mload(0x33a0), 1, PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[278] + coefficients[279] * adjustments[17]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[278]*/ mload(0x2700),

                                       mulmod(/*coefficients[279]*/ mload(0x2720),

                                              /*adjustments[17]*/mload(0x5020),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/pubkey_addr: column17_row8214 - (column17_row4118 + 1).

              let val := addmod(

                /*column17_row8214*/ mload(0x36e0),

                sub(PRIME, addmod(/*column17_row4118*/ mload(0x36a0), 1, PRIME)),

                PRIME)



              // Numerator: point - trace_generator^(8192 * (trace_length / 8192 - 1)).

              // val *= numerators[9].

              val := mulmod(val, mload(0x4dc0), PRIME)

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[280] + coefficients[281] * adjustments[21]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[280]*/ mload(0x2740),

                                       mulmod(/*coefficients[281]*/ mload(0x2760),

                                              /*adjustments[21]*/mload(0x50a0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/message_value0: column17_row4119 - column20_row30.

              let val := addmod(

                /*column17_row4119*/ mload(0x36c0),

                sub(PRIME, /*column20_row30*/ mload(0x3c80)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[282] + coefficients[283] * adjustments[17]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[282]*/ mload(0x2780),

                                       mulmod(/*coefficients[283]*/ mload(0x27a0),

                                              /*adjustments[17]*/mload(0x5020),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for ecdsa/pubkey_value0: column17_row23 - column19_row7.

              let val := addmod(

                /*column17_row23*/ mload(0x33c0),

                sub(PRIME, /*column19_row7*/ mload(0x3860)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 8192) - 1.

              // val *= denominator_invs[20].

              val := mulmod(val, mload(0x4960), PRIME)



              // res += val * (coefficients[284] + coefficients[285] * adjustments[17]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[284]*/ mload(0x27c0),

                                       mulmod(/*coefficients[285]*/ mload(0x27e0),

                                              /*adjustments[17]*/mload(0x5020),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for checkpoints/req_pc_init_addr: column17_row150 - initial_checkpoints_addr.

              let val := addmod(

                /*column17_row150*/ mload(0x3520),

                sub(PRIME, /*initial_checkpoints_addr*/ mload(0x360)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - 1.

              // val *= denominator_invs[3].

              val := mulmod(val, mload(0x4740), PRIME)



              // res += val * (coefficients[286] + coefficients[287] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[286]*/ mload(0x2800),

                                       mulmod(/*coefficients[287]*/ mload(0x2820),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for checkpoints/req_pc_final_addr: column17_row150 - final_checkpoints_addr.

              let val := addmod(

                /*column17_row150*/ mload(0x3520),

                sub(PRIME, /*final_checkpoints_addr*/ mload(0x380)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point - trace_generator^(256 * (trace_length / 256 - 1)).

              // val *= denominator_invs[22].

              val := mulmod(val, mload(0x49a0), PRIME)



              // res += val * (coefficients[288] + coefficients[289] * adjustments[4]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[288]*/ mload(0x2840),

                                       mulmod(/*coefficients[289]*/ mload(0x2860),

                                              /*adjustments[4]*/mload(0x4e80),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for checkpoints/required_fp_addr: column17_row86 - (column17_row150 + 1).

              let val := addmod(

                /*column17_row86*/ mload(0x3460),

                sub(PRIME, addmod(/*column17_row150*/ mload(0x3520), 1, PRIME)),

                PRIME)



              // Numerator: 1.

              // val *= 1.

              // val := mulmod(val, 1, PRIME).

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[290] + coefficients[291] * adjustments[10]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[290]*/ mload(0x2880),

                                       mulmod(/*coefficients[291]*/ mload(0x28a0),

                                              /*adjustments[10]*/mload(0x4f40),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for checkpoints/required_pc_next_addr: (column17_row406 - column17_row150) * (column17_row406 - (column17_row150 + 2)).

              let val := mulmod(

                addmod(

                  /*column17_row406*/ mload(0x3640),

                  sub(PRIME, /*column17_row150*/ mload(0x3520)),

                  PRIME),

                addmod(

                  /*column17_row406*/ mload(0x3640),

                  sub(PRIME, addmod(/*column17_row150*/ mload(0x3520), 2, PRIME)),

                  PRIME),

                PRIME)



              // Numerator: point - trace_generator^(256 * (trace_length / 256 - 1)).

              // val *= numerators[10].

              val := mulmod(val, mload(0x4de0), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[292] + coefficients[293] * adjustments[22]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[292]*/ mload(0x28c0),

                                       mulmod(/*coefficients[293]*/ mload(0x28e0),

                                              /*adjustments[22]*/mload(0x50c0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for checkpoints/req_pc: (column17_row406 - column17_row150) * (column17_row151 - column17_row0).

              let val := mulmod(

                addmod(

                  /*column17_row406*/ mload(0x3640),

                  sub(PRIME, /*column17_row150*/ mload(0x3520)),

                  PRIME),

                addmod(

                  /*column17_row151*/ mload(0x3540),

                  sub(PRIME, /*column17_row0*/ mload(0x3200)),

                  PRIME),

                PRIME)



              // Numerator: point - trace_generator^(256 * (trace_length / 256 - 1)).

              // val *= numerators[10].

              val := mulmod(val, mload(0x4de0), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[294] + coefficients[295] * adjustments[22]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[294]*/ mload(0x2900),

                                       mulmod(/*coefficients[295]*/ mload(0x2920),

                                              /*adjustments[22]*/mload(0x50c0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



              {

              // Constraint expression for checkpoints/req_fp: (column17_row406 - column17_row150) * (column17_row87 - column19_row9).

              let val := mulmod(

                addmod(

                  /*column17_row406*/ mload(0x3640),

                  sub(PRIME, /*column17_row150*/ mload(0x3520)),

                  PRIME),

                addmod(

                  /*column17_row87*/ mload(0x3480),

                  sub(PRIME, /*column19_row9*/ mload(0x38a0)),

                  PRIME),

                PRIME)



              // Numerator: point - trace_generator^(256 * (trace_length / 256 - 1)).

              // val *= numerators[10].

              val := mulmod(val, mload(0x4de0), PRIME)

              // Denominator: point^(trace_length / 256) - 1.

              // val *= denominator_invs[12].

              val := mulmod(val, mload(0x4860), PRIME)



              // res += val * (coefficients[296] + coefficients[297] * adjustments[22]).

              res := addmod(res,

                            mulmod(val,

                                   add(/*coefficients[296]*/ mload(0x2940),

                                       mulmod(/*coefficients[297]*/ mload(0x2960),

                                              /*adjustments[22]*/mload(0x50c0),

                      PRIME)),

                      PRIME),

                      PRIME)

              }



            mstore(0, res)

            return(0, 0x20)

            }

        }

    }

}

contract CpuPublicInputOffsets {

    // The following constants are offsets of data expected in the public input.

    uint256 internal constant OFFSET_LOG_N_STEPS = 0;

    uint256 internal constant OFFSET_RC_MIN = 1;

    uint256 internal constant OFFSET_RC_MAX = 2;

    uint256 internal constant OFFSET_LAYOUT_CODE = 3;

    uint256 internal constant OFFSET_PROGRAM_BEGIN_ADDR = 4;

    uint256 internal constant OFFSET_PROGRAM_STOP_PTR = 5;

    uint256 internal constant OFFSET_EXECUTION_BEGIN_ADDR = 6;

    uint256 internal constant OFFSET_EXECUTION_STOP_PTR = 7;

    uint256 internal constant OFFSET_OUTPUT_BEGIN_ADDR = 8;

    uint256 internal constant OFFSET_OUTPUT_STOP_PTR = 9;

    uint256 internal constant OFFSET_PEDERSEN_BEGIN_ADDR = 10;

    uint256 internal constant OFFSET_PEDERSEN_STOP_PTR = 11;

    uint256 internal constant OFFSET_RANGE_CHECK_BEGIN_ADDR = 12;

    uint256 internal constant OFFSET_RANGE_CHECK_STOP_PTR = 13;

    uint256 internal constant OFFSET_ECDSA_BEGIN_ADDR = 14;

    uint256 internal constant OFFSET_ECDSA_STOP_PTR = 15;

    uint256 internal constant OFFSET_CHECKPOINTS_BEGIN_PTR = 16;

    uint256 internal constant OFFSET_CHECKPOINTS_STOP_PTR = 17;

    uint256 internal constant OFFSET_N_PUBLIC_MEMORY_PAGES = 18;

    uint256 internal constant OFFSET_PUBLIC_MEMORY = 19;



    uint256 internal constant N_WORDS_PER_PUBLIC_MEMORY_ENTRY = 2;



    // The format of the public input, starting at OFFSET_PUBLIC_MEMORY is as follows:

    //   * For each page:

    //     * First address in the page (this field is not included for the first page).

    //     * Page size.

    //     * Page hash.

    //   * Padding cell address.

    //   * Padding cell value.

    //   # All data above this line, appears in the initial seed of the proof.

    //   * For each page:

    //     * Cumulative product.



    function getOffsetPageSize(uint256 pageId) internal pure returns (uint256) {

        return OFFSET_PUBLIC_MEMORY + 3 * pageId;

    }



    function getOffsetPageHash(uint256 pageId) internal pure returns (uint256) {

        return OFFSET_PUBLIC_MEMORY + 3 * pageId + 1;

    }



    function getOffsetPageAddr(uint256 pageId) internal pure returns (uint256) {

        require(pageId >= 1, "Address of page 0 is not part of the public input.");

        return OFFSET_PUBLIC_MEMORY + 3 * pageId - 1;

    }



    /*

      Returns the offset of the address of the padding cell. The offset of the padding cell value

      can be obtained by adding 1 to the result.

    */

    function getOffsetPaddingCell(uint256 nPages) internal pure returns (uint256) {

        return OFFSET_PUBLIC_MEMORY + 3 * nPages - 1;

    }



    function getOffsetPageProd(uint256 pageId, uint256 nPages) internal pure returns (uint256) {

        return OFFSET_PUBLIC_MEMORY + 3 * nPages + 1 + pageId;

    }



    function getPublicInputLength(uint256 nPages) internal pure returns (uint256) {

        return OFFSET_PUBLIC_MEMORY + 4 * nPages + 1;

    }



}

contract PeriodicColumnContract {

    function compute(uint256 x) external pure returns(uint256 result);

}

contract IFactRegistry {

    /*

      Returns true if the given fact was previously registered in the contract.

    */

    function isValid(bytes32 fact)

        external view

        returns(bool);

}

contract IMerkleVerifier {

    uint256 constant internal MAX_N_MERKLE_VERIFIER_QUERIES =  128;



    function verify(

        uint256 channelPtr,

        uint256 queuePtr,

        bytes32 root,

        uint256 n)

        internal view

        returns (bytes32 hash);

}

contract IQueryableFactRegistry is IFactRegistry {



    /*

      Returns true if at least one fact has been registered.

    */

    function hasRegisteredFact()

        external view

        returns(bool);



}

contract IStarkVerifier {



    function verifyProof(

        uint256[] memory proofParams,

        uint256[] memory proof,

        uint256[] memory publicInput

    )

        internal view;

}

contract MemoryMap {

    /*

      We store the state of the verifer in a contiguous chunk of memory.

      The offsets of the different fields are listed below.

      E.g. The offset of the i'th hash is [mm_hashes + i].

    */

    uint256 constant internal CHANNEL_STATE_SIZE = 3;

    uint256 constant internal MAX_N_QUERIES =  48;

    uint256 constant internal FRI_QUEUE_SIZE = MAX_N_QUERIES;



    uint256 constant internal MAX_SUPPORTED_MAX_FRI_STEP = 4;



    uint256 constant internal MM_EVAL_DOMAIN_SIZE =                          0x0;

    uint256 constant internal MM_BLOW_UP_FACTOR =                            0x1;

    uint256 constant internal MM_LOG_EVAL_DOMAIN_SIZE =                      0x2;

    uint256 constant internal MM_PROOF_OF_WORK_BITS =                        0x3;

    uint256 constant internal MM_EVAL_DOMAIN_GENERATOR =                     0x4;

    uint256 constant internal MM_PUBLIC_INPUT_PTR =                          0x5;

    uint256 constant internal MM_TRACE_COMMITMENT =                          0x6; // uint256[2]

    uint256 constant internal MM_OODS_COMMITMENT =                           0x8;

    uint256 constant internal MM_N_UNIQUE_QUERIES =                          0x9;

    uint256 constant internal MM_CHANNEL =                                   0xa; // uint256[3]

    uint256 constant internal MM_MERKLE_QUEUE =                              0xd; // uint256[96]

    uint256 constant internal MM_FRI_QUEUE =                                0x6d; // uint256[144]

    uint256 constant internal MM_FRI_QUERIES_DELIMITER =                    0xfd;

    uint256 constant internal MM_FRI_CTX =                                  0xfe; // uint256[40]

    uint256 constant internal MM_FRI_STEPS_PTR =                           0x126;

    uint256 constant internal MM_FRI_EVAL_POINTS =                         0x127; // uint256[10]

    uint256 constant internal MM_FRI_COMMITMENTS =                         0x131; // uint256[10]

    uint256 constant internal MM_FRI_LAST_LAYER_DEG_BOUND =                0x13b;

    uint256 constant internal MM_FRI_LAST_LAYER_PTR =                      0x13c;

    uint256 constant internal MM_CONSTRAINT_POLY_ARGS_START =              0x13d;

    uint256 constant internal MM_PERIODIC_COLUMN__PEDERSEN__POINTS__X =    0x13d;

    uint256 constant internal MM_PERIODIC_COLUMN__PEDERSEN__POINTS__Y =    0x13e;

    uint256 constant internal MM_PERIODIC_COLUMN__ECDSA__GENERATOR_POINTS__X = 0x13f;

    uint256 constant internal MM_PERIODIC_COLUMN__ECDSA__GENERATOR_POINTS__Y = 0x140;

    uint256 constant internal MM_TRACE_LENGTH =                            0x141;

    uint256 constant internal MM_OFFSET_SIZE =                             0x142;

    uint256 constant internal MM_HALF_OFFSET_SIZE =                        0x143;

    uint256 constant internal MM_INITIAL_AP =                              0x144;

    uint256 constant internal MM_INITIAL_PC =                              0x145;

    uint256 constant internal MM_FINAL_AP =                                0x146;

    uint256 constant internal MM_FINAL_PC =                                0x147;

    uint256 constant internal MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM = 0x148;

    uint256 constant internal MM_MEMORY__MULTI_COLUMN_PERM__HASH_INTERACTION_ELM0 = 0x149;

    uint256 constant internal MM_MEMORY__MULTI_COLUMN_PERM__PERM__PUBLIC_MEMORY_PROD = 0x14a;

    uint256 constant internal MM_RC16__PERM__INTERACTION_ELM =             0x14b;

    uint256 constant internal MM_RC16__PERM__PUBLIC_MEMORY_PROD =          0x14c;

    uint256 constant internal MM_RC_MIN =                                  0x14d;

    uint256 constant internal MM_RC_MAX =                                  0x14e;

    uint256 constant internal MM_PEDERSEN__SHIFT_POINT_X =                 0x14f;

    uint256 constant internal MM_PEDERSEN__SHIFT_POINT_Y =                 0x150;

    uint256 constant internal MM_INITIAL_PEDERSEN_ADDR =                   0x151;

    uint256 constant internal MM_INITIAL_RC_ADDR =                         0x152;

    uint256 constant internal MM_ECDSA__SIG_CONFIG_ALPHA =                 0x153;

    uint256 constant internal MM_ECDSA__SIG_CONFIG_SHIFT_POINT_X =         0x154;

    uint256 constant internal MM_ECDSA__SIG_CONFIG_SHIFT_POINT_Y =         0x155;

    uint256 constant internal MM_ECDSA__SIG_CONFIG_BETA =                  0x156;

    uint256 constant internal MM_INITIAL_ECDSA_ADDR =                      0x157;

    uint256 constant internal MM_INITIAL_CHECKPOINTS_ADDR =                0x158;

    uint256 constant internal MM_FINAL_CHECKPOINTS_ADDR =                  0x159;

    uint256 constant internal MM_TRACE_GENERATOR =                         0x15a;

    uint256 constant internal MM_OODS_POINT =                              0x15b;

    uint256 constant internal MM_INTERACTION_ELEMENTS =                    0x15c; // uint256[3]

    uint256 constant internal MM_COEFFICIENTS =                            0x15f; // uint256[298]

    uint256 constant internal MM_OODS_VALUES =                             0x289; // uint256[173]

    uint256 constant internal MM_CONSTRAINT_POLY_ARGS_END =                0x336;

    uint256 constant internal MM_COMPOSITION_OODS_VALUES =                 0x336; // uint256[2]

    uint256 constant internal MM_OODS_EVAL_POINTS =                        0x338; // uint256[48]

    uint256 constant internal MM_OODS_COEFFICIENTS =                       0x368; // uint256[175]

    uint256 constant internal MM_TRACE_QUERY_RESPONSES =                   0x417; // uint256[1056]

    uint256 constant internal MM_COMPOSITION_QUERY_RESPONSES =             0x837; // uint256[96]

    uint256 constant internal MM_LOG_N_STEPS =                             0x897;

    uint256 constant internal MM_N_PUBLIC_MEM_ENTRIES =                    0x898;

    uint256 constant internal MM_N_PUBLIC_MEM_PAGES =                      0x899;

    uint256 constant internal MM_CONTEXT_SIZE =                            0x89a;

}

contract MemoryPageFactRegistryConstants {

    // A page based on a list of pairs (address, value).

    // In this case, memoryHash = hash(address, value, address, value, address, value, ...).

    uint256 internal constant REGULAR_PAGE = 0;

    // A page based on adjacent memory cells, starting from a given address.

    // In this case, memoryHash = hash(value, value, value, ...).

    uint256 internal constant CONTINUOUS_PAGE = 1;

}

contract MerkleStatementVerifier is IMerkleVerifier {

    MerkleStatementContract merkleStatementContract;



    constructor(address merkleStatementContractAddress) internal {

        merkleStatementContract = MerkleStatementContract(merkleStatementContractAddress);

    }



    // Computes the hash of the Merkle statement, and verifies that it is registered in the

    // Merkle Fact Registry. Receives as input the queuePtr (as address), its length

    // the numbers of queries n, and the root. The channelPtr is is ignored.

    function verify(uint256 /*channelPtr*/, uint256 queuePtr, bytes32 root, uint256 n) internal view

        returns(bytes32) {

        bytes32 statement;

        require(n <= MAX_N_MERKLE_VERIFIER_QUERIES, "TOO_MANY_MERKLE_QUERIES");



        assembly {

            let dataToHashPtrStart := mload(0x40) // freePtr.

            let dataToHashPtrCur := dataToHashPtrStart



            let queEndPtr := add(queuePtr, mul(n, 0x40))



            for { } lt(queuePtr, queEndPtr) { } {

                mstore(dataToHashPtrCur, mload(queuePtr))

                dataToHashPtrCur := add(dataToHashPtrCur, 0x20)

                queuePtr := add(queuePtr, 0x20)

            }



            mstore(dataToHashPtrCur, root)

            dataToHashPtrCur := add(dataToHashPtrCur, 0x20)

            mstore(0x40, dataToHashPtrCur)



            statement := keccak256(dataToHashPtrStart, sub(dataToHashPtrCur, dataToHashPtrStart))

        }

        require(merkleStatementContract.isValid(statement), "INVALIDATED_MERKLE_STATEMENT");

        return root;

    }



}

contract MerkleVerifier is IMerkleVerifier {



    function getHashMask() internal pure returns(uint256) {

        // Default implementation.

        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;

    }



    /*

      Verifies a Merkle tree decommitment for n leaves in a Merkle tree with N leaves.



      The inputs data sits in the queue at queuePtr.

      Each slot in the queue contains a 32 bytes leaf index and a 32 byte leaf value.

      The indices need to be in the range [N..2*N-1] and strictly incrementing.

      Decommitments are read from the channel in the ctx.



      The input data is destroyed during verification.

    */

    function verify(

        uint256 channelPtr,

        uint256 queuePtr,

        bytes32 root,

        uint256 n)

        internal view

        returns (bytes32 hash)

    {

        uint256 lhashMask = getHashMask();

        require(n <= MAX_N_MERKLE_VERIFIER_QUERIES, "TOO_MANY_MERKLE_QUERIES");



        assembly {

            // queuePtr + i * 0x40 gives the i'th index in the queue.

            // hashesPtr + i * 0x40 gives the i'th hash in the queue.

            let hashesPtr := add(queuePtr, 0x20)

            let queueSize := mul(n, 0x40)

            let slotSize := 0x40



            // The items are in slots [0, n-1].

            let rdIdx := 0

            let wrIdx := 0 // = n % n.



            // Iterate the queue until we hit the root.

            let index := mload(add(rdIdx, queuePtr))

            let proofPtr := mload(channelPtr)



            // while(index > 1).

            for { } gt(index, 1) { } {

                let siblingIndex := xor(index, 1)

                // sibblingOffset := 0x20 * lsb(siblingIndex).

                let sibblingOffset := mulmod(siblingIndex, 0x20, 0x40)



                // Store the hash corresponding to index in the correct slot.

                // 0 if index is even and 0x20 if index is odd.

                // The hash of the sibling will be written to the other slot.

                mstore(xor(0x20, sibblingOffset), mload(add(rdIdx, hashesPtr)))

                rdIdx := addmod(rdIdx, slotSize, queueSize)



                // Inline channel operation:

                // Assume we are going to read a new hash from the proof.

                // If this is not the case add(proofPtr, 0x20) will be reverted.

                let newHashPtr := proofPtr

                proofPtr := add(proofPtr, 0x20)



                // Push index/2 into the queue, before reading the next index.

                // The order is important, as otherwise we may try to read from an empty queue (in

                // the case where we are working on one item).

                // wrIdx will be updated after writing the relevant hash to the queue.

                mstore(add(wrIdx, queuePtr), div(index, 2))



                // Load the next index from the queue and check if it is our sibling.

                index := mload(add(rdIdx, queuePtr))

                if eq(index, siblingIndex) {

                    // Take sibling from queue rather than from proof.

                    newHashPtr := add(rdIdx, hashesPtr)

                    // Revert reading from proof.

                    proofPtr := sub(proofPtr, 0x20)

                    rdIdx := addmod(rdIdx, slotSize, queueSize)



                    // Index was consumed, read the next one.

                    // Note that the queue can't be empty at this point.

                    // The index of the parent of the current node was already pushed into the

                    // queue, and the parent is never the sibling.

                    index := mload(add(rdIdx, queuePtr))

                }



                mstore(sibblingOffset, mload(newHashPtr))



                // Push the new hash to the end of the queue.

                mstore(add(wrIdx, hashesPtr), and(lhashMask, keccak256(0x00, 0x40)))

                wrIdx := addmod(wrIdx, slotSize, queueSize)

            }

            hash := mload(add(rdIdx, hashesPtr))



            // Update the proof pointer in the context.

            mstore(channelPtr, proofPtr)

        }

        // emit LogBool(hash == root);

        require(hash == root, "INVALID_MERKLE_PROOF");

    }

}

contract PrimeFieldElement0 {

    uint256 constant internal K_MODULUS =

    0x800000000000011000000000000000000000000000000000000000000000001;

    uint256 constant internal K_MODULUS_MASK =

    0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    uint256 constant internal K_MONTGOMERY_R =

    0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1;

    uint256 constant internal K_MONTGOMERY_R_INV =

    0x40000000000001100000000000012100000000000000000000000000000000;

    uint256 constant internal GENERATOR_VAL = 3;

    uint256 constant internal ONE_VAL = 1;

    uint256 constant internal GEN1024_VAL =

    0x659d83946a03edd72406af6711825f5653d9e35dc125289a206c054ec89c4f1;



    function fromMontgomery(uint256 val) internal pure returns (uint256 res) {

        // uint256 res = fmul(val, kMontgomeryRInv);

        assembly {

            res := mulmod(val,

                          0x40000000000001100000000000012100000000000000000000000000000000,

                          0x800000000000011000000000000000000000000000000000000000000000001)

        }

        return res;

    }



    function fromMontgomeryBytes(bytes32 bs) internal pure returns (uint256) {

        // Assuming bs is a 256bit bytes object, in Montgomery form, it is read into a field

        // element.

        uint256 res = uint256(bs);

        return fromMontgomery(res);

    }



    function toMontgomeryInt(uint256 val) internal pure returns (uint256 res) {

        //uint256 res = fmul(val, kMontgomeryR);

        assembly {

            res := mulmod(val,

                          0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1,

                          0x800000000000011000000000000000000000000000000000000000000000001)

        }

        return res;

    }



    function fmul(uint256 a, uint256 b) internal pure returns (uint256 res) {

        //uint256 res = mulmod(a, b, kModulus);

        assembly {

            res := mulmod(a, b,

                0x800000000000011000000000000000000000000000000000000000000000001)

        }

        return res;

    }



    function fadd(uint256 a, uint256 b) internal pure returns (uint256 res) {

        // uint256 res = addmod(a, b, kModulus);

        assembly {

            res := addmod(a, b,

                0x800000000000011000000000000000000000000000000000000000000000001)

        }

        return res;

    }



    function fsub(uint256 a, uint256 b) internal pure returns (uint256 res) {

        // uint256 res = addmod(a, kModulus - b, kModulus);

        assembly {

            res := addmod(

                a,

                sub(0x800000000000011000000000000000000000000000000000000000000000001, b),

                0x800000000000011000000000000000000000000000000000000000000000001)

        }

        return res;

    }



    function fpow(uint256 val, uint256 exp) internal view returns (uint256) {

        return expmod(val, exp, K_MODULUS);

    }



    function expmod(uint256 base, uint256 exponent, uint256 modulus)

        internal view returns (uint256 res)

    {

        assembly {

            let p := mload(0x40)

            mstore(p, 0x20)                  // Length of Base.

            mstore(add(p, 0x20), 0x20)       // Length of Exponent.

            mstore(add(p, 0x40), 0x20)       // Length of Modulus.

            mstore(add(p, 0x60), base)       // Base.

            mstore(add(p, 0x80), exponent)   // Exponent.

            mstore(add(p, 0xa0), modulus)    // Modulus.

            // Call modexp precompile.

            if iszero(staticcall(gas, 0x05, p, 0xc0, p, 0x20)) {

                revert(0, 0)

            }

            res := mload(p)

        }

    }



    function inverse(uint256 val) internal view returns (uint256) {

        return expmod(val, K_MODULUS - 2, K_MODULUS);

    }

}

contract Prng is PrimeFieldElement0 {

    function storePrng(uint256 statePtr, bytes32 digest, uint256 counter)

        internal pure {

        assembly {

            mstore(statePtr, digest)

            mstore(add(statePtr, 0x20), counter)

        }

    }



    function loadPrng(uint256 statePtr)

        internal pure

        returns (bytes32, uint256) {

        bytes32 digest;

        uint256 counter;



        assembly {

            digest := mload(statePtr)

            counter := mload(add(statePtr, 0x20))

        }



        return (digest, counter);

    }



    function initPrng(uint256 prngPtr, bytes32 publicInputHash)

        internal pure

    {

        storePrng(prngPtr, /*keccak256(publicInput)*/ publicInputHash, 0);

    }



    /*

      Auxiliary function for getRandomBytes.

    */

    function getRandomBytesInner(bytes32 digest, uint256 counter)

        internal pure

        returns (bytes32, uint256, bytes32)

    {

        // returns 32 bytes (for random field elements or four queries at a time).

        bytes32 randomBytes = keccak256(abi.encodePacked(digest, counter));



        return (digest, counter + 1, randomBytes);

    }



    /*

      Returns 32 bytes. Used for a random field element, or for 4 query indices.

    */

    function getRandomBytes(uint256 prngPtr)

        internal pure

        returns (bytes32 randomBytes)

    {

        bytes32 digest;

        uint256 counter;

        (digest, counter) = loadPrng(prngPtr);



        // returns 32 bytes (for random field elements or four queries at a time).

        (digest, counter, randomBytes) = getRandomBytesInner(digest, counter);



        storePrng(prngPtr, digest, counter);

        return randomBytes;

    }



    function mixSeedWithBytes(uint256 prngPtr, bytes memory dataBytes)

        internal pure

    {

        bytes32 digest;



        assembly {

            digest := mload(prngPtr)

        }

        initPrng(prngPtr, keccak256(abi.encodePacked(digest, dataBytes)));

    }



    function getPrngDigest(uint256 prngPtr)

        internal pure

        returns (bytes32 digest)

    {

        assembly {

           digest := mload(prngPtr)

        }

    }

}

contract StarkParameters is PrimeFieldElement0 {

    uint256 constant internal N_COEFFICIENTS = 298;

    uint256 constant internal N_INTERACTION_ELEMENTS = 3;

    uint256 constant internal MASK_SIZE = 173;

    uint256 constant internal N_ROWS_IN_MASK = 78;

    uint256 constant internal N_COLUMNS_IN_MASK = 22;

    uint256 constant internal N_COLUMNS_IN_TRACE0 = 21;

    uint256 constant internal N_COLUMNS_IN_TRACE1 = 1;

    uint256 constant internal CONSTRAINTS_DEGREE_BOUND = 2;

    uint256 constant internal N_OODS_VALUES = MASK_SIZE + CONSTRAINTS_DEGREE_BOUND;

    uint256 constant internal N_OODS_COEFFICIENTS = N_OODS_VALUES;

    uint256 constant internal MAX_FRI_STEP = 3;



    // ---------- // Air specific constants. ----------

    uint256 constant internal PUBLIC_MEMORY_STEP = 8;

    uint256 constant internal PEDERSEN_BUILTIN_RATIO = 8;

    uint256 constant internal PEDERSEN_BUILTIN_REPETITIONS = 4;

    uint256 constant internal RC_BUILTIN_RATIO = 8;

    uint256 constant internal RC_N_PARTS = 8;

    uint256 constant internal ECDSA_BUILTIN_RATIO = 512;

    uint256 constant internal ECDSA_BUILTIN_REPETITIONS = 1;

    uint256 constant internal LAYOUT_CODE = 6579576;

    uint256 constant internal LOG_CPU_COMPONENT_HEIGHT = 4;

}

contract VerifierChannel is Prng {



    /*

      We store the state of the channel in uint256[3] as follows:

        [0] proof pointer.

        [1] prng digest.

        [2] prng counter.

    */

    uint256 constant internal CHANNEL_STATE_SIZE = 3;



    event LogValue(bytes32 val);



    event SendRandomnessEvent(uint256 val);



    event ReadFieldElementEvent(uint256 val);



    event ReadHashEvent(bytes32 val);



    function getPrngPtr(uint256 channelPtr)

        internal pure

        returns (uint256)

    {

        return channelPtr + 0x20;

    }



    function initChannel(uint256 channelPtr, uint256 proofPtr, bytes32 publicInputHash)

        internal pure

    {

        assembly {

            // Skip 0x20 bytes length at the beginning of the proof.

            mstore(channelPtr, add(proofPtr, 0x20))

        }



        initPrng(getPrngPtr(channelPtr), publicInputHash);

    }



    function sendFieldElements(uint256 channelPtr, uint256 nElements, uint256 targetPtr)

        internal pure

    {

        require(nElements < 0x1000000, "Overflow protection failed.");

        assembly {

            let PRIME := 0x800000000000011000000000000000000000000000000000000000000000001

            let PRIME_MON_R_INV := 0x40000000000001100000000000012100000000000000000000000000000000

            let PRIME_MASK := 0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

            let digestPtr := add(channelPtr, 0x20)

            let counterPtr := add(channelPtr, 0x40)



            let endPtr := add(targetPtr, mul(nElements, 0x20))

            for { } lt(targetPtr, endPtr) { targetPtr := add(targetPtr, 0x20) } {

                // *targetPtr = getRandomFieldElement(getPrngPtr(channelPtr));



                let fieldElement := PRIME

                // while (fieldElement >= PRIME).

                for { } iszero(lt(fieldElement, PRIME)) { } {

                    // keccak256(abi.encodePacked(digest, counter));

                    fieldElement := and(keccak256(digestPtr, 0x40), PRIME_MASK)

                    // *counterPtr += 1;

                    mstore(counterPtr, add(mload(counterPtr), 1))

                }

                // *targetPtr = fromMontgomery(fieldElement);

                mstore(targetPtr, mulmod(fieldElement, PRIME_MON_R_INV, PRIME))

                // emit ReadFieldElementEvent(fieldElement);

                // log1(targetPtr, 0x20, 0x4bfcc54f35095697be2d635fb0706801e13637312eff0cedcdfc254b3b8c385e);

            }

        }

    }



    /*

      Sends random queries and returns an array of queries sorted in ascending order.

      Generates count queries in the range [0, mask] and returns the number of unique queries.

      Note that mask is of the form 2^k-1 (for some k).



      Note that queriesOutPtr may be (and is) inteleaved with other arrays. The stride parameter

      is passed to indicate the distance between every two entries to the queries array, i.e.

      stride = 0x20*(number of interleaved arrays).

    */

    function sendRandomQueries(

        uint256 channelPtr, uint256 count, uint256 mask, uint256 queriesOutPtr, uint256 stride)

        internal pure returns (uint256)

    {

        uint256 val;

        uint256 shift = 0;

        uint256 endPtr = queriesOutPtr;

        for (uint256 i = 0; i < count; i++) {

            if (shift == 0) {

                val = uint256(getRandomBytes(getPrngPtr(channelPtr)));

                shift = 0x100;

            }

            shift -= 0x40;

            uint256 queryIdx = (val >> shift) & mask;

            // emit sendRandomnessEvent(queryIdx);



            uint256 ptr = endPtr;

            uint256 curr;

            // Insert new queryIdx in the correct place like insertion sort.



            while (ptr > queriesOutPtr) {

                assembly {

                    curr := mload(sub(ptr, stride))

                }



                if (queryIdx >= curr) {

                    break;

                }



                assembly {

                    mstore(ptr, curr)

                }

                ptr -= stride;

            }



            if (queryIdx != curr) {

                assembly {

                    mstore(ptr, queryIdx)

                }

                endPtr += stride;

            } else {

                // Revert right shuffling.

                while (ptr < endPtr) {

                    assembly {

                        mstore(ptr, mload(add(ptr, stride)))

                        ptr := add(ptr, stride)

                    }

                }

            }

        }



        return (endPtr - queriesOutPtr) / stride;

    }



    function readBytes(uint256 channelPtr, bool mix)

        internal pure

        returns (bytes32)

    {

        uint256 proofPtr;

        bytes32 val;



        assembly {

            proofPtr := mload(channelPtr)

            val := mload(proofPtr)

            mstore(channelPtr, add(proofPtr, 0x20))

        }

        if (mix) {

            // inline: Prng.mixSeedWithBytes(getPrngPtr(channelPtr), abi.encodePacked(val));

            assembly {

                let digestPtr := add(channelPtr, 0x20)

                let counterPtr := add(digestPtr, 0x20)

                mstore(counterPtr, val)

                // prng.digest := keccak256(digest||val), nonce was written earlier.

                mstore(digestPtr, keccak256(digestPtr, 0x40))

                // prng.counter := 0.

                mstore(counterPtr, 0)

            }

        }



        return val;

    }



    function readHash(uint256 channelPtr, bool mix)

        internal pure

        returns (bytes32)

    {

        bytes32 val = readBytes(channelPtr, mix);

        // emit ReadHashEvent(val);



        return val;

    }



    function readFieldElement(uint256 channelPtr, bool mix)

        internal pure returns (uint256) {

        uint256 val = fromMontgomery(uint256(readBytes(channelPtr, mix)));

        // emit ReadFieldElementEvent(val);



        return val;

    }



    function verifyProofOfWork(uint256 channelPtr, uint256 proofOfWorkBits) internal pure {

        if (proofOfWorkBits == 0) {

            return;

        }



        uint256 proofOfWorkDigest;

        assembly {

            // [0:29] := 0123456789abcded || digest || workBits.

            mstore(0, 0x0123456789abcded000000000000000000000000000000000000000000000000)

            let digest := mload(add(channelPtr, 0x20))

            mstore(0x8, digest)

            mstore8(0x28, proofOfWorkBits)

            mstore(0, keccak256(0, 0x29))



            let proofPtr := mload(channelPtr)

            mstore(0x20, mload(proofPtr))

            // proofOfWorkDigest:= keccak256(keccak256(0123456789abcded || digest || workBits) || nonce).

            proofOfWorkDigest := keccak256(0, 0x28)



            mstore(0, digest)

            // prng.digest := keccak256(digest||nonce), nonce was written earlier.

            mstore(add(channelPtr, 0x20), keccak256(0, 0x28))

            // prng.counter := 0.

            mstore(add(channelPtr, 0x40), 0)



            mstore(channelPtr, add(proofPtr, 0x8))

        }



        uint256 proofOfWorkThreshold = uint256(1) << (256 - proofOfWorkBits);

        require(proofOfWorkDigest < proofOfWorkThreshold, "Proof of work check failed.");

    }

}

contract FactRegistry is IQueryableFactRegistry {

    // Mapping: fact hash -> true.

    mapping (bytes32 => bool) private verifiedFact;



    // Indicates whether the Fact Registry has at least one fact registered.

    bool anyFactRegistered;



    /*

      Checks if a fact has been verified.

    */

    function isValid(bytes32 fact)

        external view

        returns(bool)

    {

        return _factCheck(fact);

    }





    /*

      This is an internal method to check if the fact is already registered.

      In current implementation of FactRegistry it's identical to isValid().

      But the check is against the local fact registry,

      So for a derived referral fact registry, it's not the same.

    */

    function _factCheck(bytes32 fact)

        internal view

        returns(bool)

    {

        return verifiedFact[fact];

    }



    function registerFact(

        bytes32 factHash

        )

        internal

    {

        // This function stores the fact hash in the mapping.

        verifiedFact[factHash] = true;



        // Mark first time off.

        if (!anyFactRegistered) {

            anyFactRegistered = true;

        }

    }



    /*

      Indicates whether at least one fact was registered.

    */

    function hasRegisteredFact()

        external view

        returns(bool)

    {

        return anyFactRegistered;

    }



}

contract FriLayer is MerkleVerifier, PrimeFieldElement0 {

    event LogGas(string name, uint256 val);



    uint256 constant internal FRI_MAX_FRI_STEP = 4;

    uint256 constant internal MAX_COSET_SIZE = 2**FRI_MAX_FRI_STEP;

    // Generator of the group of size MAX_COSET_SIZE: GENERATOR_VAL**((PRIME - 1)/MAX_COSET_SIZE).

    uint256 constant internal FRI_GROUP_GEN =

    0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539;



    uint256 constant internal FRI_GROUP_SIZE = 0x20 * MAX_COSET_SIZE;

    uint256 constant internal FRI_CTX_TO_COSET_EVALUATIONS_OFFSET = 0;

    uint256 constant internal FRI_CTX_TO_FRI_GROUP_OFFSET = FRI_GROUP_SIZE;

    uint256 constant internal FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET =

    FRI_CTX_TO_FRI_GROUP_OFFSET + FRI_GROUP_SIZE;



    uint256 constant internal FRI_CTX_SIZE =

    FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET + (FRI_GROUP_SIZE / 2);



    function nextLayerElementFromTwoPreviousLayerElements(

        uint256 fX, uint256 fMinusX, uint256 evalPoint, uint256 xInv)

        internal pure

        returns (uint256 res)

    {

        // Folding formula:

        // f(x)  = g(x^2) + xh(x^2)

        // f(-x) = g((-x)^2) - xh((-x)^2) = g(x^2) - xh(x^2)

        // =>

        // 2g(x^2) = f(x) + f(-x)

        // 2h(x^2) = (f(x) - f(-x))/x

        // => The 2*interpolation at evalPoint is:

        // 2*(g(x^2) + evalPoint*h(x^2)) = f(x) + f(-x) + evalPoint*(f(x) - f(-x))*xInv.

        //

        // Note that multiplying by 2 doesn't affect the degree,

        // so we can just agree to do that on both the prover and verifier.

        assembly {

            // PRIME is PrimeFieldElement0.K_MODULUS.

            let PRIME := 0x800000000000011000000000000000000000000000000000000000000000001

            // Note that whenever we call add(), the result is always less than 2*PRIME,

            // so there are no overflows.

            res := addmod(add(fX, fMinusX),

                   mulmod(mulmod(evalPoint, xInv, PRIME),

                   add(fX, /*-fMinusX*/sub(PRIME, fMinusX)), PRIME), PRIME)

        }

    }



    /*

      Reads 4 elements, and applies 2 + 1 FRI transformations to obtain a single element.



      FRI layer n:                              f0 f1  f2 f3

      -----------------------------------------  \ / -- \ / -----------

      FRI layer n+1:                              f0    f2

      -------------------------------------------- \ ---/ -------------

      FRI layer n+2:                                 f0



      The basic FRI transformation is described in nextLayerElementFromTwoPreviousLayerElements().

    */

    function do2FriSteps(

        uint256 friHalfInvGroupPtr, uint256 evaluationsOnCosetPtr, uint256 cosetOffset_,

        uint256 friEvalPoint)

    internal pure returns (uint256 nextLayerValue, uint256 nextXInv) {

        assembly {

            let PRIME := 0x800000000000011000000000000000000000000000000000000000000000001

            let friEvalPointDivByX := mulmod(friEvalPoint, cosetOffset_, PRIME)



            let f0 := mload(evaluationsOnCosetPtr)

            {

                let f1 := mload(add(evaluationsOnCosetPtr, 0x20))



                // f0 < 3P ( = 1 + 1 + 1).

                f0 := add(add(f0, f1),

                             mulmod(friEvalPointDivByX,

                                    add(f0, /*-fMinusX*/sub(PRIME, f1)),

                                    PRIME))

            }



            let f2 := mload(add(evaluationsOnCosetPtr, 0x40))

            {

                let f3 := mload(add(evaluationsOnCosetPtr, 0x60))

                f2 := addmod(add(f2, f3),

                             mulmod(add(f2, /*-fMinusX*/sub(PRIME, f3)),

                                    mulmod(mload(add(friHalfInvGroupPtr, 0x20)),

                                           friEvalPointDivByX,

                                           PRIME),

                                    PRIME),

                             PRIME)

            }



            {

                let newXInv := mulmod(cosetOffset_, cosetOffset_, PRIME)

                nextXInv := mulmod(newXInv, newXInv, PRIME)

            }



            // f0 + f2 < 4P ( = 3 + 1).

            nextLayerValue := addmod(add(f0, f2),

                          mulmod(mulmod(friEvalPointDivByX, friEvalPointDivByX, PRIME),

                                 add(f0, /*-fMinusX*/sub(PRIME, f2)),

                                 PRIME),

                          PRIME)

        }

    }



    /*

      Reads 8 elements, and applies 4 + 2 + 1 FRI transformation to obtain a single element.



      See do2FriSteps for more detailed explanation.

    */

    function do3FriSteps(

        uint256 friHalfInvGroupPtr, uint256 evaluationsOnCosetPtr, uint256 cosetOffset_,

        uint256 friEvalPoint)

    internal pure returns (uint256 nextLayerValue, uint256 nextXInv) {

        assembly {

            let PRIME := 0x800000000000011000000000000000000000000000000000000000000000001

            let MPRIME := 0x8000000000000110000000000000000000000000000000000000000000000010

            let f0 := mload(evaluationsOnCosetPtr)



            let friEvalPointDivByX := mulmod(friEvalPoint, cosetOffset_, PRIME)

            let friEvalPointDivByXSquared := mulmod(friEvalPointDivByX, friEvalPointDivByX, PRIME)

            let imaginaryUnit := mload(add(friHalfInvGroupPtr, 0x20))



            {

                let f1 := mload(add(evaluationsOnCosetPtr, 0x20))



                // f0 < 3P ( = 1 + 1 + 1).

                f0 := add(add(f0, f1),

                          mulmod(friEvalPointDivByX,

                                 add(f0, /*-fMinusX*/sub(PRIME, f1)),

                                 PRIME))

            }

            {

                let f2 := mload(add(evaluationsOnCosetPtr, 0x40))

                {

                    let f3 := mload(add(evaluationsOnCosetPtr, 0x60))



                    // f2 < 3P ( = 1 + 1 + 1).

                    f2 := add(add(f2, f3),

                              mulmod(add(f2, /*-fMinusX*/sub(PRIME, f3)),

                                     mulmod(friEvalPointDivByX, imaginaryUnit, PRIME),

                                     PRIME))

                }



                // f0 < 7P ( = 3 + 3 + 1).

                f0 := add(add(f0, f2),

                          mulmod(friEvalPointDivByXSquared,

                                 add(f0, /*-fMinusX*/sub(MPRIME, f2)),

                                 PRIME))

            }

            {

                let f4 := mload(add(evaluationsOnCosetPtr, 0x80))

                {

                    let friEvalPointDivByX2 := mulmod(friEvalPointDivByX,

                                                    mload(add(friHalfInvGroupPtr, 0x40)), PRIME)

                    {

                        let f5 := mload(add(evaluationsOnCosetPtr, 0xa0))



                        // f4 < 3P ( = 1 + 1 + 1).

                        f4 := add(add(f4, f5),

                                  mulmod(friEvalPointDivByX2,

                                         add(f4, /*-fMinusX*/sub(PRIME, f5)),

                                         PRIME))

                    }



                    let f6 := mload(add(evaluationsOnCosetPtr, 0xc0))

                    {

                        let f7 := mload(add(evaluationsOnCosetPtr, 0xe0))



                        // f6 < 3P ( = 1 + 1 + 1).

                        f6 := add(add(f6, f7),

                                  mulmod(add(f6, /*-fMinusX*/sub(PRIME, f7)),

                                         // friEvalPointDivByX2 * imaginaryUnit ==

                                         // friEvalPointDivByX * mload(add(friHalfInvGroupPtr, 0x60)).

                                         mulmod(friEvalPointDivByX2, imaginaryUnit, PRIME),

                                         PRIME))

                    }



                    // f4 < 7P ( = 3 + 3 + 1).

                    f4 := add(add(f4, f6),

                              mulmod(mulmod(friEvalPointDivByX2, friEvalPointDivByX2, PRIME),

                                     add(f4, /*-fMinusX*/sub(MPRIME, f6)),

                                     PRIME))

                }



                // f0, f4 < 7P -> f0 + f4 < 14P && 9P < f0 + (MPRIME - f4) < 23P.

                nextLayerValue :=

                   addmod(add(f0, f4),

                          mulmod(mulmod(friEvalPointDivByXSquared, friEvalPointDivByXSquared, PRIME),

                                 add(f0, /*-fMinusX*/sub(MPRIME, f4)),

                                 PRIME),

                          PRIME)

            }



            {

                let xInv2 := mulmod(cosetOffset_, cosetOffset_, PRIME)

                let xInv4 := mulmod(xInv2, xInv2, PRIME)

                nextXInv := mulmod(xInv4, xInv4, PRIME)

            }





        }

    }



    /*

      This function reads 16 elements, and applies 8 + 4 + 2 + 1 fri transformation

      to obtain a single element.



      See do2FriSteps for more detailed explanation.

    */

    function do4FriSteps(

        uint256 friHalfInvGroupPtr, uint256 evaluationsOnCosetPtr, uint256 cosetOffset_,

        uint256 friEvalPoint)

    internal pure returns (uint256 nextLayerValue, uint256 nextXInv) {

        assembly {

            let friEvalPointDivByXTessed

            let PRIME := 0x800000000000011000000000000000000000000000000000000000000000001

            let MPRIME := 0x8000000000000110000000000000000000000000000000000000000000000010

            let f0 := mload(evaluationsOnCosetPtr)



            let friEvalPointDivByX := mulmod(friEvalPoint, cosetOffset_, PRIME)

            let imaginaryUnit := mload(add(friHalfInvGroupPtr, 0x20))



            {

                let f1 := mload(add(evaluationsOnCosetPtr, 0x20))



                // f0 < 3P ( = 1 + 1 + 1).

                f0 := add(add(f0, f1),

                          mulmod(friEvalPointDivByX,

                                 add(f0, /*-fMinusX*/sub(PRIME, f1)),

                                 PRIME))

            }

            {

                let f2 := mload(add(evaluationsOnCosetPtr, 0x40))

                {

                    let f3 := mload(add(evaluationsOnCosetPtr, 0x60))



                    // f2 < 3P ( = 1 + 1 + 1).

                    f2 := add(add(f2, f3),

                                mulmod(add(f2, /*-fMinusX*/sub(PRIME, f3)),

                                       mulmod(friEvalPointDivByX, imaginaryUnit, PRIME),

                                       PRIME))

                }

                {

                    let friEvalPointDivByXSquared := mulmod(friEvalPointDivByX, friEvalPointDivByX, PRIME)

                    friEvalPointDivByXTessed := mulmod(friEvalPointDivByXSquared, friEvalPointDivByXSquared, PRIME)



                    // f0 < 7P ( = 3 + 3 + 1).

                    f0 := add(add(f0, f2),

                              mulmod(friEvalPointDivByXSquared,

                                     add(f0, /*-fMinusX*/sub(MPRIME, f2)),

                                     PRIME))

                }

            }

            {

                let f4 := mload(add(evaluationsOnCosetPtr, 0x80))

                {

                    let friEvalPointDivByX2 := mulmod(friEvalPointDivByX,

                                                      mload(add(friHalfInvGroupPtr, 0x40)), PRIME)

                    {

                        let f5 := mload(add(evaluationsOnCosetPtr, 0xa0))



                        // f4 < 3P ( = 1 + 1 + 1).

                        f4 := add(add(f4, f5),

                                  mulmod(friEvalPointDivByX2,

                                         add(f4, /*-fMinusX*/sub(PRIME, f5)),

                                         PRIME))

                    }



                    let f6 := mload(add(evaluationsOnCosetPtr, 0xc0))

                    {

                        let f7 := mload(add(evaluationsOnCosetPtr, 0xe0))



                        // f6 < 3P ( = 1 + 1 + 1).

                        f6 := add(add(f6, f7),

                                  mulmod(add(f6, /*-fMinusX*/sub(PRIME, f7)),

                                         // friEvalPointDivByX2 * imaginaryUnit ==

                                         // friEvalPointDivByX * mload(add(friHalfInvGroupPtr, 0x60)).

                                         mulmod(friEvalPointDivByX2, imaginaryUnit, PRIME),

                                         PRIME))

                    }



                    // f4 < 7P ( = 3 + 3 + 1).

                    f4 := add(add(f4, f6),

                              mulmod(mulmod(friEvalPointDivByX2, friEvalPointDivByX2, PRIME),

                                     add(f4, /*-fMinusX*/sub(MPRIME, f6)),

                                     PRIME))

                }



                // f0 < 15P ( = 7 + 7 + 1).

                f0 := add(add(f0, f4),

                          mulmod(friEvalPointDivByXTessed,

                                 add(f0, /*-fMinusX*/sub(MPRIME, f4)),

                                 PRIME))

            }

            {

                let f8 := mload(add(evaluationsOnCosetPtr, 0x100))

                {

                    let friEvalPointDivByX4 := mulmod(friEvalPointDivByX,

                                                      mload(add(friHalfInvGroupPtr, 0x80)), PRIME)

                    {

                        let f9 := mload(add(evaluationsOnCosetPtr, 0x120))



                        // f8 < 3P ( = 1 + 1 + 1).

                        f8 := add(add(f8, f9),

                                  mulmod(friEvalPointDivByX4,

                                         add(f8, /*-fMinusX*/sub(PRIME, f9)),

                                         PRIME))

                    }



                    let f10 := mload(add(evaluationsOnCosetPtr, 0x140))

                    {

                        let f11 := mload(add(evaluationsOnCosetPtr, 0x160))

                        // f10 < 3P ( = 1 + 1 + 1).

                        f10 := add(add(f10, f11),

                                   mulmod(add(f10, /*-fMinusX*/sub(PRIME, f11)),

                                          // friEvalPointDivByX4 * imaginaryUnit ==

                                          // friEvalPointDivByX * mload(add(friHalfInvGroupPtr, 0xa0)).

                                          mulmod(friEvalPointDivByX4, imaginaryUnit, PRIME),

                                          PRIME))

                    }



                    // f8 < 7P ( = 3 + 3 + 1).

                    f8 := add(add(f8, f10),

                              mulmod(mulmod(friEvalPointDivByX4, friEvalPointDivByX4, PRIME),

                                     add(f8, /*-fMinusX*/sub(MPRIME, f10)),

                                     PRIME))

                }

                {

                    let f12 := mload(add(evaluationsOnCosetPtr, 0x180))

                    {

                        let friEvalPointDivByX6 := mulmod(friEvalPointDivByX,

                                                          mload(add(friHalfInvGroupPtr, 0xc0)), PRIME)

                        {

                            let f13 := mload(add(evaluationsOnCosetPtr, 0x1a0))



                            // f12 < 3P ( = 1 + 1 + 1).

                            f12 := add(add(f12, f13),

                                       mulmod(friEvalPointDivByX6,

                                              add(f12, /*-fMinusX*/sub(PRIME, f13)),

                                              PRIME))

                        }



                        let f14 := mload(add(evaluationsOnCosetPtr, 0x1c0))

                        {

                            let f15 := mload(add(evaluationsOnCosetPtr, 0x1e0))



                            // f14 < 3P ( = 1 + 1 + 1).

                            f14 := add(add(f14, f15),

                                       mulmod(add(f14, /*-fMinusX*/sub(PRIME, f15)),

                                              // friEvalPointDivByX6 * imaginaryUnit ==

                                              // friEvalPointDivByX * mload(add(friHalfInvGroupPtr, 0xe0)).

                                              mulmod(friEvalPointDivByX6, imaginaryUnit, PRIME),

                                              PRIME))

                        }



                        // f12 < 7P ( = 3 + 3 + 1).

                        f12 := add(add(f12, f14),

                                   mulmod(mulmod(friEvalPointDivByX6, friEvalPointDivByX6, PRIME),

                                          add(f12, /*-fMinusX*/sub(MPRIME, f14)),

                                          PRIME))

                    }



                    // f8 < 15P ( = 7 + 7 + 1).

                    f8 := add(add(f8, f12),

                              mulmod(mulmod(friEvalPointDivByXTessed, imaginaryUnit, PRIME),

                                     add(f8, /*-fMinusX*/sub(MPRIME, f12)),

                                     PRIME))

                }



                // f0, f8 < 15P -> f0 + f8 < 30P && 16P < f0 + (MPRIME - f8) < 31P.

                nextLayerValue :=

                    addmod(add(f0, f8),

                           mulmod(mulmod(friEvalPointDivByXTessed, friEvalPointDivByXTessed, PRIME),

                                  add(f0, /*-fMinusX*/sub(MPRIME, f8)),

                                  PRIME),

                           PRIME)

            }



            {

                let xInv2 := mulmod(cosetOffset_, cosetOffset_, PRIME)

                let xInv4 := mulmod(xInv2, xInv2, PRIME)

                let xInv8 := mulmod(xInv4, xInv4, PRIME)

                nextXInv := mulmod(xInv8, xInv8, PRIME)

            }

        }

    }



    /*

      Gathers the "cosetSize" elements that belong to the same coset

      as the item at the top of the FRI queue and stores them in ctx[MM_FRI_STEP_VALUES:].



      Returns

        friQueueHead - friQueueHead_ + 0x60  * (# elements that were taken from the queue).

        cosetIdx - the start index of the coset that was gathered.

        cosetOffset_ - the xInv field element that corresponds to cosetIdx.

    */

    function gatherCosetInputs(

        uint256 channelPtr, uint256 friCtx, uint256 friQueueHead_, uint256 cosetSize)

        internal pure returns (uint256 friQueueHead, uint256 cosetIdx, uint256 cosetOffset_) {



        uint256 evaluationsOnCosetPtr = friCtx + FRI_CTX_TO_COSET_EVALUATIONS_OFFSET;

        uint256 friGroupPtr = friCtx + FRI_CTX_TO_FRI_GROUP_OFFSET;



        friQueueHead = friQueueHead_;

        assembly {

            let queueItemIdx := mload(friQueueHead)

            // The coset index is represented by the most significant bits of the queue item index.

            cosetIdx := and(queueItemIdx, not(sub(cosetSize, 1)))

            let nextCosetIdx := add(cosetIdx, cosetSize)

            let PRIME := 0x800000000000011000000000000000000000000000000000000000000000001



            // Get the algebraic coset offset:

            // I.e. given c*g^(-k) compute c, where

            //      g is the generator of the coset group.

            //      k is bitReverse(offsetWithinCoset, log2(cosetSize)).

            //

            // To do this we multiply the algebraic coset offset at the top of the queue (c*g^(-k))

            // by the group element that corresponds to the index inside the coset (g^k).

            cosetOffset_ := mulmod(

                /*(c*g^(-k)*/ mload(add(friQueueHead, 0x40)),

                /*(g^k)*/     mload(add(friGroupPtr,

                                        mul(/*offsetWithinCoset*/sub(queueItemIdx, cosetIdx),

                                            0x20))),

                PRIME)



            let proofPtr := mload(channelPtr)



            for { let index := cosetIdx } lt(index, nextCosetIdx) { index := add(index, 1) } {

                // Inline channel operation:

                // Assume we are going to read the next element from the proof.

                // If this is not the case add(proofPtr, 0x20) will be reverted.

                let fieldElementPtr := proofPtr

                proofPtr := add(proofPtr, 0x20)



                // Load the next index from the queue and check if it is our sibling.

                if eq(index, queueItemIdx) {

                    // Take element from the queue rather than from the proof

                    // and convert it back to Montgomery form for Merkle verification.

                    fieldElementPtr := add(friQueueHead, 0x20)



                    // Revert the read from proof.

                    proofPtr := sub(proofPtr, 0x20)



                    // Reading the next index here is safe due to the

                    // delimiter after the queries.

                    friQueueHead := add(friQueueHead, 0x60)

                    queueItemIdx := mload(friQueueHead)

                }



                // Note that we apply the modulo operation to convert the field elements we read

                // from the proof to canonical representation (in the range [0, PRIME - 1]).

                mstore(evaluationsOnCosetPtr, mod(mload(fieldElementPtr), PRIME))

                evaluationsOnCosetPtr := add(evaluationsOnCosetPtr, 0x20)

            }



            mstore(channelPtr, proofPtr)

        }

    }



    /*

      Returns the bit reversal of num assuming it has the given number of bits.

      For example, if we have numberOfBits = 6 and num = (0b)1101 == (0b)001101,

      the function will return (0b)101100.

    */

    function bitReverse(uint256 num, uint256 numberOfBits)

    internal pure

        returns(uint256 numReversed)

    {

        assert((numberOfBits == 256) || (num < 2 ** numberOfBits));

        uint256 n = num;

        uint256 r = 0;

        for (uint256 k = 0; k < numberOfBits; k++) {

            r = (r * 2) | (n % 2);

            n = n / 2;

        }

        return r;

    }



    /*

      Initializes the FRI group and half inv group in the FRI context.

    */

    function initFriGroups(uint256 friCtx) internal view {

        uint256 friGroupPtr = friCtx + FRI_CTX_TO_FRI_GROUP_OFFSET;

        uint256 friHalfInvGroupPtr = friCtx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET;



        // FRI_GROUP_GEN is the coset generator.

        // Raising it to the (MAX_COSET_SIZE - 1) power gives us the inverse.

        uint256 genFriGroup = FRI_GROUP_GEN;



        uint256 genFriGroupInv = fpow(genFriGroup, (MAX_COSET_SIZE - 1));



        uint256 lastVal = ONE_VAL;

        uint256 lastValInv = ONE_VAL;

        uint256 prime = PrimeFieldElement0.K_MODULUS;

        assembly {

            // ctx[mmHalfFriInvGroup + 0] = ONE_VAL;

            mstore(friHalfInvGroupPtr, lastValInv)

            // ctx[mmFriGroup + 0] = ONE_VAL;

            mstore(friGroupPtr, lastVal)

            // ctx[mmFriGroup + 1] = fsub(0, ONE_VAL);

            mstore(add(friGroupPtr, 0x20), sub(prime, lastVal))

        }



        // To compute [1, -1 (== g^n/2), g^n/4, -g^n/4, ...]

        // we compute half the elements and derive the rest using negation.

        uint256 halfCosetSize = MAX_COSET_SIZE / 2;

        for (uint256 i = 1; i < halfCosetSize; i++) {

            lastVal = fmul(lastVal, genFriGroup);

            lastValInv = fmul(lastValInv, genFriGroupInv);

            uint256 idx = bitReverse(i, FRI_MAX_FRI_STEP-1);



            assembly {

                // ctx[mmHalfFriInvGroup + idx] = lastValInv;

                mstore(add(friHalfInvGroupPtr, mul(idx, 0x20)), lastValInv)

                // ctx[mmFriGroup + 2*idx] = lastVal;

                mstore(add(friGroupPtr, mul(idx, 0x40)), lastVal)

                // ctx[mmFriGroup + 2*idx + 1] = fsub(0, lastVal);

                mstore(add(friGroupPtr, add(mul(idx, 0x40), 0x20)), sub(prime, lastVal))

            }

        }

    }



    /*

      Operates on the coset of size friFoldedCosetSize that start at index.



      It produces 3 outputs:

        1. The field elements that result from doing FRI reductions on the coset.

        2. The pointInv elements for the location that corresponds to the first output.

        3. The root of a Merkle tree for the input layer.



      The input is read either from the queue or from the proof depending on data availability.

      Since the function reads from the queue it returns an updated head pointer.

    */

    function doFriSteps(

        uint256 friCtx, uint256 friQueueTail, uint256 cosetOffset_, uint256 friEvalPoint,

        uint256 friCosetSize, uint256 index, uint256 merkleQueuePtr)

        internal pure {

        uint256 friValue;



        uint256 evaluationsOnCosetPtr = friCtx + FRI_CTX_TO_COSET_EVALUATIONS_OFFSET;

        uint256 friHalfInvGroupPtr = friCtx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET;



        // Compare to expected FRI step sizes in order of likelihood, step size 3 being most common.

        if (friCosetSize == 8) {

            (friValue, cosetOffset_) = do3FriSteps(

                friHalfInvGroupPtr, evaluationsOnCosetPtr, cosetOffset_, friEvalPoint);

        } else if (friCosetSize == 4) {

            (friValue, cosetOffset_) = do2FriSteps(

                friHalfInvGroupPtr, evaluationsOnCosetPtr, cosetOffset_, friEvalPoint);

        } else if (friCosetSize == 16) {

            (friValue, cosetOffset_) = do4FriSteps(

                friHalfInvGroupPtr, evaluationsOnCosetPtr, cosetOffset_, friEvalPoint);

        } else {

            require(false, "Only step sizes of 2, 3 or 4 are supported.");

        }



        uint256 lhashMask = getHashMask();

        assembly {

            let indexInNextStep := div(index, friCosetSize)

            mstore(merkleQueuePtr, indexInNextStep)

            mstore(add(merkleQueuePtr, 0x20), and(lhashMask, keccak256(evaluationsOnCosetPtr,

                                                                          mul(0x20,friCosetSize))))



            mstore(friQueueTail, indexInNextStep)

            mstore(add(friQueueTail, 0x20), friValue)

            mstore(add(friQueueTail, 0x40), cosetOffset_)

        }

    }



    /*

      Computes the FRI step with eta = log2(friCosetSize) for all the live queries.

      The input and output data is given in array of triplets:

          (query index, FRI value, FRI inversed point)

      in the address friQueuePtr (which is &ctx[mmFriQueue:]).



      The function returns the number of live queries remaining after computing the FRI step.



      The number of live queries decreases whenever multiple query points in the same

      coset are reduced to a single query in the next FRI layer.



      As the function computes the next layer it also collects that data from

      the previous layer for Merkle verification.

    */

    function computeNextLayer(

        uint256 channelPtr, uint256 friQueuePtr, uint256 merkleQueuePtr, uint256 nQueries,

        uint256 friEvalPoint, uint256 friCosetSize, uint256 friCtx)

        internal pure returns (uint256 nLiveQueries) {

        uint256 merkleQueueTail = merkleQueuePtr;

        uint256 friQueueHead = friQueuePtr;

        uint256 friQueueTail = friQueuePtr;

        uint256 friQueueEnd = friQueueHead + (0x60 * nQueries);



        do {

            uint256 cosetOffset;

            uint256 index;

            (friQueueHead, index, cosetOffset) = gatherCosetInputs(

                channelPtr, friCtx, friQueueHead, friCosetSize);



            doFriSteps(

                friCtx, friQueueTail, cosetOffset, friEvalPoint, friCosetSize, index,

                merkleQueueTail);



            merkleQueueTail += 0x40;

            friQueueTail += 0x60;

        } while (friQueueHead < friQueueEnd);

        return (friQueueTail - friQueuePtr) / 0x60;

    }



}

contract FriStatementContract is FriLayer, FactRegistry {

    /*

      Compute a single FRI layer of size friStepSize at evaluationPoint starting from input

      friQueue, and the extra witnesses in the "proof" channel. Also check that the input and

      witnesses belong to a Merkle tree with root expectedRoot, again using witnesses from "proof".

      After verification, register the FRI fact hash, which is:

      keccak256(

          evaluationPoint,

          friStepSize,

          keccak256(friQueue_input),

          keccak256(friQueue_output),  // The FRI queue after proccessing the FRI layer

          expectedRoot

      )



      Note that this function is used as external, but declared public to avoid copying the arrays.

    */

    function verifyFRI(

        uint256[] memory proof,

        uint256[] memory friQueue,

        uint256 evaluationPoint,

        uint256 friStepSize,

        uint256 expectedRoot) public {



        require (friStepSize <= FRI_MAX_FRI_STEP, "FRI step size too large");

        /*

          The friQueue should have of 3*nQueries + 1 elements, beginning with nQueries triplets

          of the form (query_index, FRI_value, FRI_inverse_point), and ending with a single buffer

          cell set to 0, which is accessed and read during the computation of the FRI layer.

        */

        require (

            friQueue.length % 3 == 1,

            "FRI Queue must be composed of triplets plus one delimiter cell");

        require (friQueue.length >= 4, "No query to process");



        uint256 mmFriCtxSize = FRI_CTX_SIZE;

        uint256 nQueries = friQueue.length / 3;

        friQueue[3*nQueries] = 0;  // NOLINT: divide-before-multiply.

        uint256 merkleQueuePtr;

        uint256 friQueuePtr;

        uint256 channelPtr;

        uint256 friCtx;

        uint256 dataToHash;



        // Verify evaluation point within valid range.

        require(evaluationPoint < K_MODULUS, "INVALID_EVAL_POINT");



        // Queries need to be in the range [2**height .. 2**(height+1)-1] strictly incrementing.

        // i.e. we need to check that Qi+1 > Qi for each i,

        // but regarding the height range - it's sufficient to check that

        // (Q1 ^ Qn) < Q1 Which affirms that all queries are within the same logarithmic step.



        // Verify FRI values and inverses are within valid range.

        // and verify that queries are strictly incrementing.

        uint256 prevQuery = 0; // If we pass height, change to: prevQuery = 1 << height - 1;

        for (uint256 i = 0; i < nQueries; i++) {

            require(friQueue[3*i] > prevQuery, "INVALID_QUERY_VALUE");

            require(friQueue[3*i+1] < K_MODULUS, "INVALID_FRI_VALUE");

            require(friQueue[3*i+2] < K_MODULUS, "INVALID_FRI_INVERSE_POINT");

            prevQuery = friQueue[3*i];

        }



        // Verify all queries are on the same logarithmic step.

        // NOLINTNEXTLINE: divide-before-multiply.

        require((friQueue[0] ^ friQueue[3*nQueries-3]) < friQueue[0], "INVALID_QUERIES_RANGE");



        // Allocate memory queues: channelPtr, merkleQueue, friCtx, dataToHash.

        assembly {

            friQueuePtr := add(friQueue, 0x20)

            channelPtr := mload(0x40) // Free pointer location.

            mstore(channelPtr, add(proof, 0x20))

            merkleQueuePtr := add(channelPtr, 0x20)

            friCtx := add(merkleQueuePtr, mul(0x40, nQueries))

            dataToHash := add(friCtx, mmFriCtxSize)

            mstore(0x40, add(dataToHash, 0xa0)) // Advance free pointer.



            mstore(dataToHash, evaluationPoint)

            mstore(add(dataToHash, 0x20), friStepSize)

            mstore(add(dataToHash, 0x80), expectedRoot)



            // Hash FRI inputs and add to dataToHash.

            mstore(add(dataToHash, 0x40), keccak256(friQueuePtr, mul(0x60, nQueries)))

        }



        initFriGroups(friCtx);



        nQueries = computeNextLayer(

            channelPtr, friQueuePtr, merkleQueuePtr, nQueries, evaluationPoint,

            2**friStepSize, /* friCosetSize = 2**friStepSize */

            friCtx);



        verify(channelPtr, merkleQueuePtr, bytes32(expectedRoot), nQueries);



        bytes32 factHash;

        assembly {

            // Hash FRI outputs and add to dataToHash.

            mstore(add(dataToHash, 0x60), keccak256(friQueuePtr, mul(0x60, nQueries)))

            factHash := keccak256(dataToHash, 0xa0)

        }



        registerFact(factHash);

    }

}

contract HornerEvaluator is PrimeFieldElement0 {

    /*

      Computes the evaluation of a polynomial f(x) = sum(a_i * x^i) on the given point.

      The coefficients of the polynomial are given in

        a_0 = coefsStart[0], ..., a_{n-1} = coefsStart[n - 1]

      where n = nCoefs = friLastLayerDegBound. Note that coefsStart is not actually an array but

      a direct pointer.

      The function requires that n is divisible by 8.

    */

    function hornerEval(uint256 coefsStart, uint256 point, uint256 nCoefs)

        internal pure

        returns (uint256) {

        uint256 result = 0;

        uint256 prime = PrimeFieldElement0.K_MODULUS;



        require(nCoefs % 8 == 0, "Number of polynomial coefficients must be divisible by 8");

        require(nCoefs < 4096, "No more than 4096 coefficients are supported");



        assembly {

            let coefsPtr := add(coefsStart, mul(nCoefs, 0x20))

            for { } gt(coefsPtr, coefsStart) { } {

                // Reduce coefsPtr by 8 field elements.

                coefsPtr := sub(coefsPtr, 0x100)



                // Apply 4 Horner steps (result := result * point + coef).

                result :=

                    add(mload(add(coefsPtr, 0x80)), mulmod(

                    add(mload(add(coefsPtr, 0xa0)), mulmod(

                    add(mload(add(coefsPtr, 0xc0)), mulmod(

                    add(mload(add(coefsPtr, 0xe0)), mulmod(

                        result,

                    point, prime)),

                    point, prime)),

                    point, prime)),

                    point, prime))



                // Apply 4 additional Horner steps.

                result :=

                    add(mload(coefsPtr), mulmod(

                    add(mload(add(coefsPtr, 0x20)), mulmod(

                    add(mload(add(coefsPtr, 0x40)), mulmod(

                    add(mload(add(coefsPtr, 0x60)), mulmod(

                        result,

                    point, prime)),

                    point, prime)),

                    point, prime)),

                    point, prime))

            }

        }



        // Since the last operation was "add" (instead of "addmod"), we need to take result % prime.

        return result % prime;

    }

}

contract MemoryAccessUtils is MemoryMap {

    function getPtr(uint256[] memory ctx, uint256 offset)

        internal pure

        returns (uint256) {

        uint256 ctxPtr;

        require(offset < MM_CONTEXT_SIZE, "Overflow protection failed");

        assembly {

            ctxPtr := add(ctx, 0x20)

        }

        return ctxPtr + offset * 0x20;

    }



    function getProofPtr(uint256[] memory proof)

        internal pure

        returns (uint256)

    {

        uint256 proofPtr;

        assembly {

            proofPtr := proof

        }

        return proofPtr;

    }



    function getChannelPtr(uint256[] memory ctx)

        internal pure

        returns (uint256) {

        uint256 ctxPtr;

        assembly {

            ctxPtr := add(ctx, 0x20)

        }

        return ctxPtr + MM_CHANNEL * 0x20;

    }



    function getQueries(uint256[] memory ctx)

        internal pure

        returns (uint256[] memory)

    {

        uint256[] memory queries;

        // Dynamic array holds length followed by values.

        uint256 offset = 0x20 + 0x20*MM_N_UNIQUE_QUERIES;

        assembly {

            queries := add(ctx, offset)

        }

        return queries;

    }



    function getMerkleQueuePtr(uint256[] memory ctx)

        internal pure

        returns (uint256)

    {

        return getPtr(ctx, MM_MERKLE_QUEUE);

    }



    function getFriSteps(uint256[] memory ctx)

        internal pure

        returns (uint256[] memory friSteps)

    {

        uint256 friStepsPtr = getPtr(ctx, MM_FRI_STEPS_PTR);

        assembly {

            friSteps := mload(friStepsPtr)

        }

    }

}

contract MemoryPageFactRegistry is FactRegistry, MemoryPageFactRegistryConstants {

    event LogMemoryPageFact(bytes32 factHash, uint256 memoryHash, uint256 prod);



    /*

      Registers a fact based of the given memory (address, value) pairs (REGULAR_PAGE).

    */

    function registerRegularMemoryPage(

        uint256[] calldata memoryPairs, uint256 z, uint256 alpha, uint256 prime)

        external returns (bytes32 factHash, uint256 memoryHash, uint256 prod)

    {

        require(memoryPairs.length < 2**20, "Too many memory values.");

        require(memoryPairs.length % 2 == 0, "Size of memoryPairs must be even.");

        require(z < prime, "Invalid value of z.");

        require(alpha < prime, "Invalid value of alpha.");

        (factHash, memoryHash, prod) = computeFactHash(memoryPairs, z, alpha, prime);

        emit LogMemoryPageFact(factHash, memoryHash, prod);



        registerFact(factHash);

    }



    function computeFactHash(

        uint256[] memory memoryPairs, uint256 z, uint256 alpha, uint256 prime)

        internal pure returns (bytes32 factHash, uint256 memoryHash, uint256 prod) {

        uint256 memorySize = memoryPairs.length / 2;



        prod = 1;



        assembly {

            let memoryPtr := add(memoryPairs, 0x20)



            // Each value of memoryPairs is a pair: (address, value).

            let lastPtr := add(memoryPtr, mul(memorySize, 0x40))

            for { let ptr := memoryPtr } lt(ptr, lastPtr) { ptr := add(ptr, 0x40) } {

                // Compute address + alpha * value.

                let address_value_lin_comb := addmod(

                    /*address*/ mload(ptr),

                    mulmod(/*value*/ mload(add(ptr, 0x20)), alpha, prime),

                    prime)

                prod := mulmod(prod, add(z, sub(prime, address_value_lin_comb)), prime)

            }



            memoryHash := keccak256(memoryPtr, mul(/*0x20 * 2*/ 0x40, memorySize))

        }



        factHash = keccak256(

            abi.encodePacked(

                REGULAR_PAGE, prime, memorySize, z, alpha, prod, memoryHash, uint256(0))

        );

    }



    /*

      Registers a fact based on the given values, assuming continuous addresses.

      values should be [value at startAddr, value at (startAddr + 1), ...].

    */

    function registerContinuousMemoryPage(  // NOLINT: external-function.

        uint256 startAddr, uint256[] memory values, uint256 z, uint256 alpha, uint256 prime)

        public returns (bytes32 factHash, uint256 memoryHash, uint256 prod)

    {

        require(values.length < 2**20, "Too many memory values.");

        require(prime < 2**254, "prime is too big for the optimizations in this function.");

        require(z < prime, "Invalid value of z.");

        require(alpha < prime, "Invalid value of alpha.");

        require(startAddr < 2**64 && startAddr < prime, "Invalid value of startAddr.");



        uint256 nValues = values.length;



        assembly {

            // Initialize prod to 1.

            prod := 1

            // Initialize valuesPtr to point to the first value in the array.

            let valuesPtr := add(values, 0x20)



            let minus_z := mod(sub(prime, z), prime)



            // Start by processing full batches of 8 cells, addr represents the last address in each

            // batch.

            let addr := add(startAddr, 7)

            let lastAddr := add(startAddr, nValues)

            for {} lt(addr, lastAddr) { addr := add(addr, 8) } {

                // Compute the product of (lin_comb - z) instead of (z - lin_comb), since we're

                // doing an even number of iterations, the result is the same.

                prod :=

                    mulmod(prod,

                    mulmod(add(add(sub(addr, 7), mulmod(

                        mload(valuesPtr), alpha, prime)), minus_z),

                    add(add(sub(addr, 6), mulmod(

                        mload(add(valuesPtr, 0x20)), alpha, prime)), minus_z),

                    prime), prime)



                prod :=

                    mulmod(prod,

                    mulmod(add(add(sub(addr, 5), mulmod(

                        mload(add(valuesPtr, 0x40)), alpha, prime)), minus_z),

                    add(add(sub(addr, 4), mulmod(

                        mload(add(valuesPtr, 0x60)), alpha, prime)), minus_z),

                    prime), prime)



                prod :=

                    mulmod(prod,

                    mulmod(add(add(sub(addr, 3), mulmod(

                        mload(add(valuesPtr, 0x80)), alpha, prime)), minus_z),

                    add(add(sub(addr, 2), mulmod(

                        mload(add(valuesPtr, 0xa0)), alpha, prime)), minus_z),

                    prime), prime)



                prod :=

                    mulmod(prod,

                    mulmod(add(add(sub(addr, 1), mulmod(

                        mload(add(valuesPtr, 0xc0)), alpha, prime)), minus_z),

                    add(add(addr, mulmod(

                        mload(add(valuesPtr, 0xe0)), alpha, prime)), minus_z),

                    prime), prime)



                valuesPtr := add(valuesPtr, 0x100)

            }



            // Handle leftover.

            // Translate addr to the beginning of the last incomplete batch.

            addr := sub(addr, 7)

            for {} lt(addr, lastAddr) { addr := add(addr, 1) } {

                let address_value_lin_comb := addmod(

                    addr, mulmod(mload(valuesPtr), alpha, prime), prime)

                prod := mulmod(prod, add(z, sub(prime, address_value_lin_comb)), prime)

                valuesPtr := add(valuesPtr, 0x20)

            }



            memoryHash := keccak256(add(values, 0x20), mul(0x20, nValues))

        }



        factHash = keccak256(

            abi.encodePacked(

                CONTINUOUS_PAGE, prime, nValues, z, alpha, prod, memoryHash, startAddr)

        );



        emit LogMemoryPageFact(factHash, memoryHash, prod);



        registerFact(factHash);

    }

}

contract MerkleStatementContract is MerkleVerifier, FactRegistry {

    /*

      This function recieves an initial merkle queue (consists of indices of leaves in the merkle

      in addition to their values) and a merkle view (contains the values of all the nodes

      required to be able to validate the queue). In case of success it registers the Merkle fact,

      which is the hash of the queue together with the resulting root.

    */

    // NOLINTNEXTLINE: external-function.

    function verifyMerkle(

        uint256[] memory merkleView,

        uint256[] memory initialMerkleQueue,

        uint256 height,

        uint256 expectedRoot

        )

        public

    {

        require(height < 200, "Height must be < 200.");

        require(

            initialMerkleQueue.length <= MAX_N_MERKLE_VERIFIER_QUERIES * 2,

            "TOO_MANY_MERKLE_QUERIES");



        uint256 merkleQueuePtr;

        uint256 channelPtr;

        uint256 nQueries;

        uint256 dataToHashPtr;

        uint256 badInput = 0;



        assembly {

            // Skip 0x20 bytes length at the beginning of the merkleView.

            let merkleViewPtr := add(merkleView, 0x20)

            // Let channelPtr point to a free space.

            channelPtr := mload(0x40) // freePtr.

            // channelPtr will point to the merkleViewPtr since the 'verify' function expects

            // a pointer to the proofPtr.

            mstore(channelPtr, merkleViewPtr)

            // Skip 0x20 bytes length at the beginning of the initialMerkleQueue.

            merkleQueuePtr := add(initialMerkleQueue, 0x20)

            // Get number of queries.

            nQueries := div(mload(initialMerkleQueue), 0x2)

            // Get a pointer to the end of initialMerkleQueue.

            let initialMerkleQueueEndPtr := add(merkleQueuePtr, mul(nQueries, 0x40))

            // Let dataToHashPtr point to a free memory.

            dataToHashPtr := add(channelPtr, 0x20) // Next freePtr.



            // Copy initialMerkleQueue to dataToHashPtr and validaite the indices.

            // The indices need to be in the range [2**height..2*(height+1)-1] and

            // strictly incrementing.



            // First index needs to be >= 2**height.

            let idxLowerLimit := shl(height, 1)

            for { } lt(merkleQueuePtr, initialMerkleQueueEndPtr) { } {

                let curIdx := mload(merkleQueuePtr)

                // badInput |= curIdx < IdxLowerLimit.

                badInput := or(badInput, lt(curIdx, idxLowerLimit))



                // The next idx must be at least curIdx + 1.

                idxLowerLimit := add(curIdx, 1)



                // Copy the pair (idx, hash) to the dataToHash array.

                mstore(dataToHashPtr, curIdx)

                mstore(add(dataToHashPtr, 0x20), mload(add(merkleQueuePtr, 0x20)))



                dataToHashPtr := add(dataToHashPtr, 0x40)

                merkleQueuePtr := add(merkleQueuePtr, 0x40)

            }



            // We need to enforce that lastIdx < 2**(height+1)

            // => fail if lastIdx >= 2**(height+1)

            // => fail if (lastIdx + 1) > 2**(height+1)

            // => fail if idxLowerLimit > 2**(height+1).

            badInput := or(badInput, gt(idxLowerLimit, shl(height, 2)))



            // Reset merkleQueuePtr.

            merkleQueuePtr := add(initialMerkleQueue, 0x20)

            // Let freePtr point to a free memory (one word after the copied queries - reserved

            // for the root).

            mstore(0x40, add(dataToHashPtr, 0x20))

        }

        require(badInput == 0, "INVALID_MERKLE_INDICES");

        bytes32 resRoot = verify(channelPtr, merkleQueuePtr, bytes32(expectedRoot), nQueries);

        bytes32 factHash;

        assembly {

            // Append the resulted root (should be the return value of verify) to dataToHashPtr.

            mstore(dataToHashPtr, resRoot)

            // Reset dataToHashPtr.

            dataToHashPtr := add(channelPtr, 0x20)

            factHash := keccak256(dataToHashPtr, add(mul(nQueries, 0x40), 0x20))

        }



        registerFact(factHash);

    }

}

contract Fri is MemoryMap, MemoryAccessUtils, HornerEvaluator, FriLayer {

    event LogGas(string name, uint256 val);



    function verifyLastLayer(uint256[] memory ctx, uint256 nPoints)

        internal view {

        uint256 friLastLayerDegBound = ctx[MM_FRI_LAST_LAYER_DEG_BOUND];

        uint256 groupOrderMinusOne = friLastLayerDegBound * ctx[MM_BLOW_UP_FACTOR] - 1;

        uint256 coefsStart = ctx[MM_FRI_LAST_LAYER_PTR];



        for (uint256 i = 0; i < nPoints; i++) {

            uint256 point = ctx[MM_FRI_QUEUE + 3*i + 2];

            // Invert point using inverse(point) == fpow(point, ord(point) - 1).



            point = fpow(point, groupOrderMinusOne);

            require(

                hornerEval(coefsStart, point, friLastLayerDegBound) == ctx[MM_FRI_QUEUE + 3*i + 1],

                "Bad Last layer value.");

        }

    }



    /*

      Verifies FRI layers.



      Upon entry and every time we pass through the "if (index < layerSize)" condition,

      ctx[mmFriQueue:] holds an array of triplets (query index, FRI value, FRI inversed point), i.e.

          ctx[mmFriQueue::3] holds query indices.

          ctx[mmFriQueue + 1::3] holds the input for the next layer.

          ctx[mmFriQueue + 2::3] holds the inverses of the evaluation points:

            ctx[mmFriQueue + 3*i + 2] = inverse(

                fpow(layerGenerator,  bitReverse(ctx[mmFriQueue + 3*i], logLayerSize)).

    */

    function friVerifyLayers(

        uint256[] memory ctx)

        internal view

    {



        uint256 friCtx = getPtr(ctx, MM_FRI_CTX);

        require(

            MAX_SUPPORTED_MAX_FRI_STEP == FRI_MAX_FRI_STEP,

            "Incosistent MAX_FRI_STEP between MemoryMap.sol and FriLayer.sol");

        initFriGroups(friCtx);

        // emit LogGas("FRI offset precomputation", gasleft());

        uint256 channelPtr = getChannelPtr(ctx);

        uint256 merkleQueuePtr = getMerkleQueuePtr(ctx);



        uint256 friStep = 1;

        uint256 nLiveQueries = ctx[MM_N_UNIQUE_QUERIES];



        // Add 0 at the end of the queries array to avoid empty array check in readNextElment.

        ctx[MM_FRI_QUERIES_DELIMITER] = 0;



        // Rather than converting all the values from Montgomery to standard form,

        // we can just pretend that the values are in standard form but all

        // the committed polynomials are multiplied by MontgomeryR.

        //

        // The values in the proof are already multiplied by MontgomeryR,

        // but the inputs from the OODS oracle need to be fixed.

        for (uint256 i = 0; i < nLiveQueries; i++ ) {

            ctx[MM_FRI_QUEUE + 3*i + 1] = fmul(ctx[MM_FRI_QUEUE + 3*i + 1], K_MONTGOMERY_R);

        }



        uint256 friQueue = getPtr(ctx, MM_FRI_QUEUE);



        uint256[] memory friSteps = getFriSteps(ctx);

        uint256 nFriSteps = friSteps.length;

        while (friStep < nFriSteps) {

            uint256 friCosetSize = 2**friSteps[friStep];



            nLiveQueries = computeNextLayer(

                channelPtr, friQueue, merkleQueuePtr, nLiveQueries,

                ctx[MM_FRI_EVAL_POINTS + friStep], friCosetSize, friCtx);



            // emit LogGas(

            //     string(abi.encodePacked("FRI layer ", bytes1(uint8(48 + friStep)))), gasleft());



            // Layer is done, verify the current layer and move to next layer.

            // ctx[mmMerkleQueue: merkleQueueIdx) holds the indices

            // and values of the merkle leaves that need verification.

            verify(

                channelPtr, merkleQueuePtr, bytes32(ctx[MM_FRI_COMMITMENTS + friStep - 1]),

                nLiveQueries);



            // emit LogGas(

            //     string(abi.encodePacked("Merkle of FRI layer ", bytes1(uint8(48 + friStep)))),

            //     gasleft());

            friStep++;

        }



        verifyLastLayer(ctx, nLiveQueries);

        // emit LogGas("last FRI layer", gasleft());

    }

}

contract FriStatementVerifier is MemoryMap, MemoryAccessUtils, VerifierChannel, HornerEvaluator {

    event LogGas(string name, uint256 val);



    FriStatementContract friStatementContract;



    constructor(address friStatementContractAddress) internal {

        friStatementContract = FriStatementContract(friStatementContractAddress);

    }



    /*

      Fast-forwards the queries and invPoints of the friQueue from before the first layer to after

      the last layer, computes the last FRI layer using horner evalations, then returns the hash

      of the final FriQueue.

    */

    function computerLastLayerHash(uint256[] memory ctx, uint256 nPoints, uint256 numLayers)

        internal view returns (bytes32 lastLayerHash) {

        uint256 friLastLayerDegBound = ctx[MM_FRI_LAST_LAYER_DEG_BOUND];

        uint256 groupOrderMinusOne = friLastLayerDegBound * ctx[MM_BLOW_UP_FACTOR] - 1;

        uint256 exponent = 1 << numLayers;

        uint256 curPointIndex = 0;

        uint256 prevQuery = 0;

        uint256 coefsStart = ctx[MM_FRI_LAST_LAYER_PTR];



        for (uint256 i = 0; i < nPoints; i++) {

            uint256 query = ctx[MM_FRI_QUEUE + 3*i] >> numLayers;

            if (query == prevQuery) {

                continue;

            }

            ctx[MM_FRI_QUEUE + 3*curPointIndex] = query;

            prevQuery = query;



            uint256 point = fpow(ctx[MM_FRI_QUEUE + 3*i + 2], exponent);

            ctx[MM_FRI_QUEUE + 3*curPointIndex + 2] = point;

            // Invert point using inverse(point) == fpow(point, ord(point) - 1).



            point = fpow(point, groupOrderMinusOne);

            ctx[MM_FRI_QUEUE + 3*curPointIndex + 1] = hornerEval(

                coefsStart, point, friLastLayerDegBound);



            curPointIndex++;

        }



        uint256 friQueue = getPtr(ctx, MM_FRI_QUEUE);

        assembly {

            lastLayerHash := keccak256(friQueue, mul(curPointIndex, 0x60))

        }

    }



    /*

      Verifies that FRI layers consistent with the computed first and last FRI layers

      have been registered in the FriStatementContract.

    */

    function friVerifyLayers(

        uint256[] memory ctx)

        internal view

    {

        uint256 channelPtr = getChannelPtr(ctx);

        uint256 nQueries = ctx[MM_N_UNIQUE_QUERIES];



        // Rather than converting all the values from Montgomery to standard form,

        // we can just pretend that the values are in standard form but all

        // the committed polynomials are multiplied by MontgomeryR.

        //

        // The values in the proof are already multiplied by MontgomeryR,

        // but the inputs from the OODS oracle need to be fixed.

        for (uint256 i = 0; i < nQueries; i++ ) {

            ctx[MM_FRI_QUEUE + 3*i + 1] = fmul(ctx[MM_FRI_QUEUE + 3*i + 1], K_MONTGOMERY_R);

        }



        uint256 friQueue = getPtr(ctx, MM_FRI_QUEUE);

        uint256 inputLayerHash;

        assembly {

            inputLayerHash := keccak256(friQueue, mul(nQueries, 0x60))

        }





        uint256[] memory friSteps = getFriSteps(ctx);

        uint256 nFriStepsLessOne = friSteps.length - 1;

        uint256 friStep = 1;

        uint256 sumSteps = friSteps[1];

        uint256[5] memory dataToHash;

        while (friStep < nFriStepsLessOne) {

            uint256 outputLayerHash = uint256(readBytes(channelPtr, true));

            dataToHash[0] = ctx[MM_FRI_EVAL_POINTS + friStep];

            dataToHash[1] = friSteps[friStep];

            dataToHash[2] = inputLayerHash;

            dataToHash[3] = outputLayerHash;

            dataToHash[4] = ctx[MM_FRI_COMMITMENTS + friStep - 1];



            // Verify statement is registered.

            require( // NOLINT: calls-loop.

                friStatementContract.isValid(keccak256(abi.encodePacked(dataToHash))),

                "INVALIDATED_FRI_STATEMENT");



            inputLayerHash = outputLayerHash;



            friStep++;

            sumSteps += friSteps[friStep];

        }



        dataToHash[0] = ctx[MM_FRI_EVAL_POINTS + friStep];

        dataToHash[1] = friSteps[friStep];

        dataToHash[2] = inputLayerHash;

        dataToHash[3] = uint256(computerLastLayerHash(ctx, nQueries, sumSteps));

        dataToHash[4] = ctx[MM_FRI_COMMITMENTS + friStep - 1];



        require(

            friStatementContract.isValid(keccak256(abi.encodePacked(dataToHash))),

            "INVALIDATED_FRI_STATEMENT");

    }

}

contract StarkVerifier is MemoryMap, MemoryAccessUtils, VerifierChannel, IStarkVerifier, Fri {

    /*

      The work required to generate an invalid proof is 2^numSecurityBits.

      Typical values: 80-128.

    */

    uint256 numSecurityBits;



    /*

      The secuirty of a proof is a composition of bits obtained by PoW and bits obtained by FRI

      queries. The verifier requires at least minProofOfWorkBits to be obtained by PoW.

      Typical values: 20-30.

    */

    uint256 minProofOfWorkBits;



    constructor(uint256 numSecurityBits_, uint256 minProofOfWorkBits_) public {

        numSecurityBits = numSecurityBits_;

        minProofOfWorkBits = minProofOfWorkBits_;

    }



    /*

      To print LogDebug messages from assembly use code like the following:



      assembly {

            let val := 0x1234

            mstore(0, val) // uint256 val

            // log to the LogDebug(uint256) topic

            log1(0, 0x20, 0x2feb477e5c8c82cfb95c787ed434e820b1a28fa84d68bbf5aba5367382f5581c)

      }



      Note that you can't use log in a contract that was called with staticcall

      (ContraintPoly, Oods,...)



      If logging is needed replace the staticcall to call and add a third argument of 0.

    */

    event LogBool(bool val);

    event LogDebug(uint256 val);

    address oodsContractAddress;



    function airSpecificInit(uint256[] memory publicInput)

        internal view returns (uint256[] memory ctx, uint256 logTraceLength);



    uint256 constant internal PROOF_PARAMS_N_QUERIES_OFFSET = 0;

    uint256 constant internal PROOF_PARAMS_LOG_BLOWUP_FACTOR_OFFSET = 1;

    uint256 constant internal PROOF_PARAMS_PROOF_OF_WORK_BITS_OFFSET = 2;

    uint256 constant internal PROOF_PARAMS_FRI_LAST_LAYER_DEG_BOUND_OFFSET = 3;

    uint256 constant internal PROOF_PARAMS_N_FRI_STEPS_OFFSET = 4;

    uint256 constant internal PROOF_PARAMS_FRI_STEPS_OFFSET = 5;



    function validateFriParams(

        uint256[] memory friSteps, uint256 logTraceLength, uint256 logFriLastLayerDegBound)

        internal pure {

        require (friSteps[0] == 0, "Only eta0 == 0 is currently supported");



        uint256 expectedLogDegBound = logFriLastLayerDegBound;

        uint256 nFriSteps = friSteps.length;

        for (uint256 i = 1; i < nFriSteps; i++) {

            uint256 friStep = friSteps[i];

            require(friStep > 0, "Only the first fri step can be 0");

            require(friStep <= 4, "Max supported fri step is 4.");

            expectedLogDegBound += friStep;

        }



        // FRI starts with a polynomial of degree 'traceLength'.

        // After applying all the FRI steps we expect to get a polynomial of degree less

        // than friLastLayerDegBound.

        require (

            expectedLogDegBound == logTraceLength, "Fri params do not match trace length");

    }



    function initVerifierParams(uint256[] memory publicInput, uint256[] memory proofParams)

        internal view returns (uint256[] memory ctx) {

        require (proofParams.length > PROOF_PARAMS_FRI_STEPS_OFFSET, "Invalid proofParams.");

        require (

            proofParams.length == (

                PROOF_PARAMS_FRI_STEPS_OFFSET + proofParams[PROOF_PARAMS_N_FRI_STEPS_OFFSET]),

            "Invalid proofParams.");

        uint256 logBlowupFactor = proofParams[PROOF_PARAMS_LOG_BLOWUP_FACTOR_OFFSET];

        require (logBlowupFactor <= 16, "logBlowupFactor must be at most 16");

        require (logBlowupFactor >= 1, "logBlowupFactor must be at least 1");



        uint256 proofOfWorkBits = proofParams[PROOF_PARAMS_PROOF_OF_WORK_BITS_OFFSET];

        require (proofOfWorkBits <= 50, "proofOfWorkBits must be at most 50");

        require (proofOfWorkBits >= minProofOfWorkBits, "minimum proofOfWorkBits not satisfied");

        require (proofOfWorkBits < numSecurityBits, "Proofs may not be purely based on PoW.");



        uint256 logFriLastLayerDegBound = (

            proofParams[PROOF_PARAMS_FRI_LAST_LAYER_DEG_BOUND_OFFSET]

        );

        require (

            logFriLastLayerDegBound <= 10, "logFriLastLayerDegBound must be at most 10.");



        uint256 nFriSteps = proofParams[PROOF_PARAMS_N_FRI_STEPS_OFFSET];

        require (nFriSteps <= 10, "Too many fri steps.");

        require (nFriSteps > 1, "Not enough fri steps.");



        uint256[] memory friSteps = new uint256[](nFriSteps);

        for (uint256 i = 0; i < nFriSteps; i++) {

            friSteps[i] = proofParams[PROOF_PARAMS_FRI_STEPS_OFFSET + i];

        }



        uint256 logTraceLength;

        (ctx, logTraceLength) = airSpecificInit(publicInput);



        validateFriParams(friSteps, logTraceLength, logFriLastLayerDegBound);



        uint256 friStepsPtr = getPtr(ctx, MM_FRI_STEPS_PTR);

        assembly {

            mstore(friStepsPtr, friSteps)

        }

        ctx[MM_FRI_LAST_LAYER_DEG_BOUND] = 2**logFriLastLayerDegBound;

        ctx[MM_TRACE_LENGTH] = 2 ** logTraceLength;



        ctx[MM_BLOW_UP_FACTOR] = 2**logBlowupFactor;

        ctx[MM_PROOF_OF_WORK_BITS] = proofOfWorkBits;



        uint256 nQueries = proofParams[PROOF_PARAMS_N_QUERIES_OFFSET];

        require (nQueries > 0, "Number of queries must be at least one");

        require (nQueries <= MAX_N_QUERIES, "Too many queries.");

        require (

            nQueries * logBlowupFactor + proofOfWorkBits >= numSecurityBits,

            "Proof params do not satisfy security requirements.");



        ctx[MM_N_UNIQUE_QUERIES] = nQueries;



        // We start with log_evalDomainSize = logTraceSize and update it here.

        ctx[MM_LOG_EVAL_DOMAIN_SIZE] = logTraceLength + logBlowupFactor;

        ctx[MM_EVAL_DOMAIN_SIZE] = 2**ctx[MM_LOG_EVAL_DOMAIN_SIZE];



        uint256 gen_evalDomain = fpow(GENERATOR_VAL, (K_MODULUS - 1) / ctx[MM_EVAL_DOMAIN_SIZE]);

        ctx[MM_EVAL_DOMAIN_GENERATOR] = gen_evalDomain;

        uint256 genTraceDomain = fpow(gen_evalDomain, ctx[MM_BLOW_UP_FACTOR]);

        ctx[MM_TRACE_GENERATOR] = genTraceDomain;

    }



    function getPublicInputHash(uint256[] memory publicInput) internal pure returns (bytes32);



    function oodsConsistencyCheck(uint256[] memory ctx) internal view;



    function getNColumnsInTrace() internal pure returns(uint256);



    function getNColumnsInComposition() internal pure returns(uint256);



    function getMmCoefficients() internal pure returns(uint256);



    function getMmOodsValues() internal pure returns(uint256);



    function getMmOodsCoefficients() internal pure returns(uint256);



    function getNCoefficients() internal pure returns(uint256);



    function getNOodsValues() internal pure returns(uint256);



    function getNOodsCoefficients() internal pure returns(uint256);



    // Interaction functions.

    // If the AIR uses interaction, the following functions should be overridden.

    function getNColumnsInTrace0() internal pure returns(uint256) {

        return getNColumnsInTrace();

    }



    function getNColumnsInTrace1() internal pure returns(uint256) {

        return 0;

    }



    function getMmInteractionElements() internal pure returns(uint256) {

        require(false, "AIR does not support interaction.");

    }



    function getNInteractionElements() internal pure returns(uint256) {

        require(false, "AIR does not support interaction.");

    }



    function hasInteraction() internal pure returns (bool) {

        return getNColumnsInTrace1() > 0;

    }



    function hashRow(uint256[] memory ctx, uint256 offset, uint256 length)

    internal pure returns (uint256 res) {

        assembly {

            res := keccak256(add(add(ctx, 0x20), offset), length)

        }

        res &= getHashMask();

    }



    /*

      Adjusts the query indices and generates evaluation points for each query index.

      The operations above are independent but we can save gas by combining them as both

      operations require us to iterate the queries array.



      Indices adjustment:

          The query indices adjustment is needed because both the Merkle verification and FRI

          expect queries "full binary tree in array" indices.

          The adjustment is simply adding evalDomainSize to each query.

          Note that evalDomainSize == 2^(#FRI layers) == 2^(Merkle tree hight).



      evalPoints generation:

          for each query index "idx" we compute the corresponding evaluation point:

              g^(bitReverse(idx, log_evalDomainSize).

    */

    function adjustQueryIndicesAndPrepareEvalPoints(uint256[] memory ctx) internal view {

        uint256 nUniqueQueries = ctx[MM_N_UNIQUE_QUERIES];

        uint256 friQueue = getPtr(ctx, MM_FRI_QUEUE);

        uint256 friQueueEnd = friQueue + nUniqueQueries * 0x60;

        uint256 evalPointsPtr = getPtr(ctx, MM_OODS_EVAL_POINTS);

        uint256 log_evalDomainSize = ctx[MM_LOG_EVAL_DOMAIN_SIZE];

        uint256 evalDomainSize = ctx[MM_EVAL_DOMAIN_SIZE];

        uint256 evalDomainGenerator = ctx[MM_EVAL_DOMAIN_GENERATOR];



        assembly {

            /*

              Returns the bit reversal of value assuming it has the given number of bits.

              numberOfBits must be <= 64.

            */

            function bitReverse(value, numberOfBits) -> res {

                // Bit reverse value by swapping 1 bit chunks then 2 bit chunks and so forth.

                // Each swap is done by masking out and shifting one of the chunks by twice its size.

                // Finally, we use div to align the result to the right.

                res := value

                // Swap 1 bit chunks.

                res := or(mul(and(res, 0x5555555555555555), 0x4),

                        and(res, 0xaaaaaaaaaaaaaaaa))

                // Swap 2 bit chunks.

                res := or(mul(and(res, 0x6666666666666666), 0x10),

                        and(res, 0x19999999999999998))

                // Swap 4 bit chunks.

                res := or(mul(and(res, 0x7878787878787878), 0x100),

                        and(res, 0x78787878787878780))

                // Swap 8 bit chunks.

                res := or(mul(and(res, 0x7f807f807f807f80), 0x10000),

                        and(res, 0x7f807f807f807f8000))

                // Swap 16 bit chunks.

                res := or(mul(and(res, 0x7fff80007fff8000), 0x100000000),

                        and(res, 0x7fff80007fff80000000))

                // Swap 32 bit chunks.

                res := or(mul(and(res, 0x7fffffff80000000), 0x10000000000000000),

                        and(res, 0x7fffffff8000000000000000))

                // Right align the result.

                res := div(res, exp(2, sub(127, numberOfBits)))

            }



            function expmod(base, exponent, modulus) -> res {

                let p := mload(0x40)

                mstore(p, 0x20)                 // Length of Base.

                mstore(add(p, 0x20), 0x20)      // Length of Exponent.

                mstore(add(p, 0x40), 0x20)      // Length of Modulus.

                mstore(add(p, 0x60), base)      // Base.

                mstore(add(p, 0x80), exponent)  // Exponent.

                mstore(add(p, 0xa0), modulus)   // Modulus.

                // Call modexp precompile.

                if iszero(staticcall(gas, 0x05, p, 0xc0, p, 0x20)) {

                    revert(0, 0)

                }

                res := mload(p)

            }



            let PRIME := 0x800000000000011000000000000000000000000000000000000000000000001



            for {} lt(friQueue, friQueueEnd) {friQueue := add(friQueue, 0x60)} {

                let queryIdx := mload(friQueue)

                // Adjust queryIdx, see comment in function description.

                let adjustedQueryIdx := add(queryIdx, evalDomainSize)

                mstore(friQueue, adjustedQueryIdx)



                // Compute the evaluation point corresponding to the current queryIdx.

                mstore(evalPointsPtr, expmod(evalDomainGenerator,

                                             bitReverse(queryIdx, log_evalDomainSize),

                                             PRIME))

                evalPointsPtr := add(evalPointsPtr, 0x20)

            }

        }

    }



    /*

      Reads query responses for nColumns from the channel with the corresponding authentication

      paths. Verifies the consistency of the authentication paths with respect to the given

      merkleRoot, and stores the query values in proofDataPtr.



      nTotalColumns is the total number of columns represented in proofDataPtr (which should be

      an array of nUniqueQueries rows of size nTotalColumns). nColumns is the number of columns

      for which data will be read by this function.

      The change to the proofDataPtr array will be as follows:

      * The first nColumns cells will be set,

      * The next nTotalColumns - nColumns will be skipped,

      * The next nColumns cells will be set,

      * The next nTotalColumns - nColumns will be skipped,

      * ...



      To set the last columns for each query simply add an offset to proofDataPtr before calling the

      function.

    */

    function readQueryResponsesAndDecommit(

        uint256[] memory ctx, uint256 nTotalColumns, uint256 nColumns, uint256 proofDataPtr,

        bytes32 merkleRoot)

         internal view {

        require(nColumns <= getNColumnsInTrace() + getNColumnsInComposition(), "Too many columns.");



        uint256 nUniqueQueries = ctx[MM_N_UNIQUE_QUERIES];

        uint256 channelPtr = getPtr(ctx, MM_CHANNEL);

        uint256 friQueue = getPtr(ctx, MM_FRI_QUEUE);

        uint256 friQueueEnd = friQueue + nUniqueQueries * 0x60;

        uint256 merkleQueuePtr = getPtr(ctx, MM_MERKLE_QUEUE);

        uint256 rowSize = 0x20 * nColumns;

        uint256 lhashMask = getHashMask();

        uint256 proofDataSkipBytes = 0x20 * (nTotalColumns - nColumns);



        assembly {

            let proofPtr := mload(channelPtr)

            let merklePtr := merkleQueuePtr



            for {} lt(friQueue, friQueueEnd) {friQueue := add(friQueue, 0x60)} {

                let merkleLeaf := and(keccak256(proofPtr, rowSize), lhashMask)

                if eq(rowSize, 0x20) {

                    // If a leaf contains only 1 field element we don't hash it.

                    merkleLeaf := mload(proofPtr)

                }



                // push(queryIdx, hash(row)) to merkleQueue.

                mstore(merklePtr, mload(friQueue))

                mstore(add(merklePtr, 0x20), merkleLeaf)

                merklePtr := add(merklePtr, 0x40)



                // Copy query responses to proofData array.

                // This array will be sent to the OODS contract.

                for {let proofDataChunk_end := add(proofPtr, rowSize)}

                        lt(proofPtr, proofDataChunk_end)

                        {proofPtr := add(proofPtr, 0x20)} {

                    mstore(proofDataPtr, mload(proofPtr))

                    proofDataPtr := add(proofDataPtr, 0x20)

                }

                proofDataPtr := add(proofDataPtr, proofDataSkipBytes)

            }



            mstore(channelPtr, proofPtr)

        }



        verify(channelPtr, merkleQueuePtr, merkleRoot, nUniqueQueries);

    }



    /*

      Computes the first FRI layer by reading the query responses and calling

      the OODS contract.



      The OODS contract will build and sum boundary constraints that check that

      the prover provided the proper evaluations for the Out of Domain Sampling.



      I.e. if the prover said that f(z) = c, the first FRI layer will include

      the term (f(x) - c)/(x-z).

    */

    function computeFirstFriLayer(uint256[] memory ctx) internal view {

        adjustQueryIndicesAndPrepareEvalPoints(ctx);

        // emit LogGas("Prepare evaluation points", gasleft());

        readQueryResponsesAndDecommit(

            ctx, getNColumnsInTrace(), getNColumnsInTrace0(), getPtr(ctx, MM_TRACE_QUERY_RESPONSES),

            bytes32(ctx[MM_TRACE_COMMITMENT]));

        // emit LogGas("Read and decommit trace", gasleft());



        if (hasInteraction()) {

            readQueryResponsesAndDecommit(

                ctx, getNColumnsInTrace(), getNColumnsInTrace1(),

                getPtr(ctx, MM_TRACE_QUERY_RESPONSES + getNColumnsInTrace0()),

                bytes32(ctx[MM_TRACE_COMMITMENT + 1]));

            // emit LogGas("Read and decommit second trace", gasleft());

        }



        readQueryResponsesAndDecommit(

            ctx, getNColumnsInComposition(), getNColumnsInComposition(),

            getPtr(ctx, MM_COMPOSITION_QUERY_RESPONSES),

            bytes32(ctx[MM_OODS_COMMITMENT]));



        // emit LogGas("Read and decommit composition", gasleft());



        address oodsAddress = oodsContractAddress;

        uint256 friQueue = getPtr(ctx, MM_FRI_QUEUE);

        uint256 returnDataSize = MAX_N_QUERIES * 0x60;

        assembly {

            // Call the OODS contract.

            if iszero(staticcall(not(0), oodsAddress, ctx,

                                 /*sizeof(ctx)*/ mul(add(mload(ctx), 1), 0x20),

                                 friQueue, returnDataSize)) {

              returndatacopy(0, 0, returndatasize)

              revert(0, returndatasize)

            }

        }

        // emit LogGas("OODS virtual oracle", gasleft());

    }



    /*

      Reads the last FRI layer (i.e. the polynomial's coefficients) from the channel.

      This differs from standard reading of channel field elements in several ways:

      -- The digest is updated by hashing it once with all coefficients simultaneously, rather than

         iteratively one by one.

      -- The coefficients are kept in Montgomery form, as is the case throughout the FRI

         computation.

      -- The coefficients are not actually read and copied elsewhere, but rather only a pointer to

         their location in the channel is stored.

    */

    function readLastFriLayer(uint256[] memory ctx)

        internal pure

    {

        uint256 lmmChannel = MM_CHANNEL;

        uint256 friLastLayerDegBound = ctx[MM_FRI_LAST_LAYER_DEG_BOUND];

        uint256 lastLayerPtr;

        uint256 badInput = 0;



        assembly {

            let primeMinusOne := 0x800000000000011000000000000000000000000000000000000000000000000

            let channelPtr := add(add(ctx, 0x20), mul(lmmChannel, 0x20))

            lastLayerPtr := mload(channelPtr)



            // Make sure all the values are valid field elements.

            let length := mul(friLastLayerDegBound, 0x20)

            let lastLayerEnd := add(lastLayerPtr, length)

            for { let coefsPtr := lastLayerPtr } lt(coefsPtr, lastLayerEnd)

                { coefsPtr := add(coefsPtr, 0x20) } {

                badInput := or(badInput, gt(mload(coefsPtr), primeMinusOne))

            }



            // Copy the digest to the proof area

            // (store it before the coefficients - this is done because

            // keccak256 needs all data to be consecutive),

            // then hash and place back in digestPtr.

            let newDigestPtr := sub(lastLayerPtr, 0x20)

            let digestPtr := add(channelPtr, 0x20)

            // Overwriting the proof to minimize copying of data.

            mstore(newDigestPtr, mload(digestPtr))



            // prng.digest := keccak256(digest||lastLayerCoefs).

            mstore(digestPtr, keccak256(newDigestPtr, add(length, 0x20)))

            // prng.counter := 0.

            mstore(add(channelPtr, 0x40), 0)



            // Note: proof pointer is not incremented until this point.

            mstore(channelPtr, lastLayerEnd)

        }



        require(badInput == 0, "Invalid field element.");

        ctx[MM_FRI_LAST_LAYER_PTR] = lastLayerPtr;

    }



    function verifyProof(

        uint256[] memory proofParams, uint256[] memory proof, uint256[] memory publicInput)

        internal view {

        // emit LogGas("Transmission", gasleft());

        uint256[] memory ctx = initVerifierParams(publicInput, proofParams);

        uint256 channelPtr = getChannelPtr(ctx);



        initChannel(channelPtr,  getProofPtr(proof), getPublicInputHash(publicInput));

        // emit LogGas("Initializations", gasleft());



        // Read trace commitment.

        ctx[MM_TRACE_COMMITMENT] = uint256(readHash(channelPtr, true));



        if (hasInteraction()) {

            // Send interaction elements.

            VerifierChannel.sendFieldElements(

                channelPtr, getNInteractionElements(), getPtr(ctx, getMmInteractionElements()));



            // Read second trace commitment.

            ctx[MM_TRACE_COMMITMENT + 1] = uint256(readHash(channelPtr, true));

        }



        VerifierChannel.sendFieldElements(

            channelPtr, getNCoefficients(), getPtr(ctx, getMmCoefficients()));

        // emit LogGas("Generate coefficients", gasleft());



        ctx[MM_OODS_COMMITMENT] = uint256(readHash(channelPtr, true));



        // Send Out of Domain Sampling point.

        VerifierChannel.sendFieldElements(channelPtr, 1, getPtr(ctx, MM_OODS_POINT));



        // Read the answers to the Out of Domain Sampling.

        uint256 lmmOodsValues = getMmOodsValues();

        for (uint256 i = lmmOodsValues; i < lmmOodsValues+getNOodsValues(); i++) {

            ctx[i] = VerifierChannel.readFieldElement(channelPtr, true);

        }

        // emit LogGas("Read OODS commitments", gasleft());

        oodsConsistencyCheck(ctx);

        // emit LogGas("OODS consistency check", gasleft());

        VerifierChannel.sendFieldElements(

            channelPtr, getNOodsCoefficients(), getPtr(ctx, getMmOodsCoefficients()));

        // emit LogGas("Generate OODS coefficients", gasleft());

        ctx[MM_FRI_COMMITMENTS] = uint256(VerifierChannel.readHash(channelPtr, true));



        uint256 nFriSteps = getFriSteps(ctx).length;

        uint256 fri_evalPointPtr = getPtr(ctx, MM_FRI_EVAL_POINTS);

        for (uint256 i = 1; i < nFriSteps - 1; i++) {

            VerifierChannel.sendFieldElements(channelPtr, 1, fri_evalPointPtr + i * 0x20);

            ctx[MM_FRI_COMMITMENTS + i] = uint256(VerifierChannel.readHash(channelPtr, true));

        }



        // Send last random FRI evaluation point.

        VerifierChannel.sendFieldElements(

            channelPtr, 1, getPtr(ctx, MM_FRI_EVAL_POINTS + nFriSteps - 1));



        // Read FRI last layer commitment.

        readLastFriLayer(ctx);



        // Generate queries.

        // emit LogGas("Read FRI commitments", gasleft());

        VerifierChannel.verifyProofOfWork(channelPtr, ctx[MM_PROOF_OF_WORK_BITS]);

        ctx[MM_N_UNIQUE_QUERIES] = VerifierChannel.sendRandomQueries(

            channelPtr, ctx[MM_N_UNIQUE_QUERIES], ctx[MM_EVAL_DOMAIN_SIZE] - 1,

            getPtr(ctx, MM_FRI_QUEUE), 0x60);

        // emit LogGas("Send queries", gasleft());



        computeFirstFriLayer(ctx);



        friVerifyLayers(ctx);

    }

}

contract CpuVerifier is StarkParameters, StarkVerifier, CpuPublicInputOffsets,

        CairoVerifierContract, MemoryPageFactRegistryConstants {

    CpuConstraintPoly constraintPoly;

    PeriodicColumnContract pedersenPointsX;

    PeriodicColumnContract pedersenPointsY;

    PeriodicColumnContract ecdsaPointsX;

    PeriodicColumnContract ecdsaPointsY;

    IFactRegistry memoryPageFactRegistry;



    constructor(

        address[] memory auxPolynomials,

        address oodsContract,

        address memoryPageFactRegistry_,

        uint256 numSecurityBits_,

        uint256 minProofOfWorkBits_)

        StarkVerifier(

            numSecurityBits_,

            minProofOfWorkBits_

        )

        public {

        constraintPoly = CpuConstraintPoly(auxPolynomials[0]);

        pedersenPointsX = PeriodicColumnContract(auxPolynomials[1]);

        pedersenPointsY = PeriodicColumnContract(auxPolynomials[2]);

        ecdsaPointsX = PeriodicColumnContract(auxPolynomials[3]);

        ecdsaPointsY = PeriodicColumnContract(auxPolynomials[4]);

        oodsContractAddress = oodsContract;

        memoryPageFactRegistry = IFactRegistry(memoryPageFactRegistry_);

    }



    function verifyProofExternal(

        uint256[] calldata proofParams, uint256[] calldata proof, uint256[] calldata publicInput)

        external {

        verifyProof(proofParams, proof, publicInput);

    }



    function getNColumnsInTrace() internal pure returns (uint256) {

        return N_COLUMNS_IN_MASK;

    }



    function getNColumnsInTrace0() internal pure returns (uint256) {

        return N_COLUMNS_IN_TRACE0;

    }



    function getNColumnsInTrace1() internal pure returns (uint256) {

        return N_COLUMNS_IN_TRACE1;

    }



    function getNColumnsInComposition() internal pure returns (uint256) {

        return CONSTRAINTS_DEGREE_BOUND;

    }



    function getMmInteractionElements() internal pure returns (uint256) {

        return MM_INTERACTION_ELEMENTS;

    }



    function getMmCoefficients() internal pure returns (uint256) {

        return MM_COEFFICIENTS;

    }



    function getMmOodsValues() internal pure returns (uint256) {

        return MM_OODS_VALUES;

    }



    function getMmOodsCoefficients() internal pure returns (uint256) {

        return MM_OODS_COEFFICIENTS;

    }



    function getNInteractionElements() internal pure returns (uint256) {

        return N_INTERACTION_ELEMENTS;

    }



    function getNCoefficients() internal pure returns (uint256) {

        return N_COEFFICIENTS;

    }



    function getNOodsValues() internal pure returns (uint256) {

        return N_OODS_VALUES;

    }



    function getNOodsCoefficients() internal pure returns (uint256) {

        return N_OODS_COEFFICIENTS;

    }



    function airSpecificInit(

        uint256[] memory publicInput

    ) internal view returns (uint256[] memory ctx, uint256 logTraceLength) {

        require(

            publicInput.length >= OFFSET_PUBLIC_MEMORY,

            "publicInput is too short.");

        ctx = new uint256[](MM_CONTEXT_SIZE);



        // Context for generated code.

        ctx[MM_OFFSET_SIZE] = 2**16;

        ctx[MM_HALF_OFFSET_SIZE] = 2**15;



        // Number of steps.

        uint256 logNSteps = publicInput[OFFSET_LOG_N_STEPS];

        require(logNSteps < 50, "Number of steps is too large.");

        ctx[MM_LOG_N_STEPS] = logNSteps;

        logTraceLength = logNSteps + LOG_CPU_COMPONENT_HEIGHT;



        // Range check limits.

        ctx[MM_RC_MIN] = publicInput[OFFSET_RC_MIN];

        ctx[MM_RC_MAX] = publicInput[OFFSET_RC_MAX];

        require(ctx[MM_RC_MIN] <= ctx[MM_RC_MAX], "rc_min must be <= rc_max");

        require(ctx[MM_RC_MAX] < ctx[MM_OFFSET_SIZE], "rc_max out of range");



        // Layout.

        require(publicInput[OFFSET_LAYOUT_CODE] == LAYOUT_CODE, "Layout code mismatch.");



        // Initial and final pc ("program" memory segment).

        ctx[MM_INITIAL_PC] = publicInput[OFFSET_PROGRAM_BEGIN_ADDR];

        ctx[MM_FINAL_PC] = publicInput[OFFSET_PROGRAM_STOP_PTR];

        // Invalid final pc may indicate that the program end was moved, or the program didn't

        // complete.

        require(ctx[MM_INITIAL_PC] == 0, "Invalid initial pc");

        require(ctx[MM_FINAL_PC] == 2, "Invalid final pc");



        // Initial and final ap ("execution" memory segment).

        ctx[MM_INITIAL_AP] = publicInput[OFFSET_EXECUTION_BEGIN_ADDR];

        ctx[MM_FINAL_AP] = publicInput[OFFSET_EXECUTION_STOP_PTR];



        {

        // "output" memory segment.

        uint256 outputBeginAddr = publicInput[OFFSET_OUTPUT_BEGIN_ADDR];

        uint256 outputStopPtr = publicInput[OFFSET_OUTPUT_STOP_PTR];

        require(outputBeginAddr <= outputStopPtr, "output begin_addr must be <= stop_ptr");

        require(outputStopPtr < 2**64, "Out of range output stop_ptr.");

        }



        // "checkpoints" memory segment.

        ctx[MM_INITIAL_CHECKPOINTS_ADDR] = publicInput[OFFSET_CHECKPOINTS_BEGIN_PTR];

        ctx[MM_FINAL_CHECKPOINTS_ADDR] = publicInput[OFFSET_CHECKPOINTS_STOP_PTR];

        require(

            ctx[MM_INITIAL_CHECKPOINTS_ADDR] <= ctx[MM_FINAL_CHECKPOINTS_ADDR],

            "checkpoints begin_addr must be <= stop_ptr");

        require(ctx[MM_FINAL_CHECKPOINTS_ADDR] < 2**64, "Out of range checkpoints stop_ptr.");

        require(

            (ctx[MM_FINAL_CHECKPOINTS_ADDR] - ctx[MM_INITIAL_CHECKPOINTS_ADDR]) % 2 == 0,

            "Checkpoints should occupy an even number of cells.");



        // "pedersen" memory segment.

        ctx[MM_INITIAL_PEDERSEN_ADDR] = publicInput[OFFSET_PEDERSEN_BEGIN_ADDR];

        require(ctx[MM_INITIAL_PEDERSEN_ADDR] < 2**64, "Out of range pedersen begin_addr.");

        uint256 pedersenStopPtr = publicInput[OFFSET_PEDERSEN_STOP_PTR];

        uint256 pedersenMaxStopPtr = ctx[MM_INITIAL_PEDERSEN_ADDR] + 3 * safeDiv(

            2 ** ctx[MM_LOG_N_STEPS], PEDERSEN_BUILTIN_RATIO);

        require(

            ctx[MM_INITIAL_PEDERSEN_ADDR] <= pedersenStopPtr &&

            pedersenStopPtr <= pedersenMaxStopPtr,

            "Invalid pedersen stop_ptr");



        // "range_check" memory segment.

        ctx[MM_INITIAL_RC_ADDR] = publicInput[OFFSET_RANGE_CHECK_BEGIN_ADDR];

        require(ctx[MM_INITIAL_RC_ADDR] < 2**64, "Out of range range_check begin_addr.");

        uint256 rcStopPtr = publicInput[OFFSET_RANGE_CHECK_STOP_PTR];

        uint256 rcMaxStopPtr =

            ctx[MM_INITIAL_RC_ADDR] + safeDiv(2 ** ctx[MM_LOG_N_STEPS], RC_BUILTIN_RATIO);

        require(

            ctx[MM_INITIAL_RC_ADDR] <= rcStopPtr &&

            rcStopPtr <= rcMaxStopPtr,

            "Invalid range_check stop_ptr");



        // "ecdsa" memory segment.

        ctx[MM_INITIAL_ECDSA_ADDR] = publicInput[OFFSET_ECDSA_BEGIN_ADDR];

        require(ctx[MM_INITIAL_ECDSA_ADDR] < 2**64, "Out of range ecdsa begin_addr.");

        uint256 ecdsaStopPtr = publicInput[OFFSET_ECDSA_STOP_PTR];

        uint256 ecdsaMaxStopPtr =

            ctx[MM_INITIAL_ECDSA_ADDR] + 2 * safeDiv(2 ** ctx[MM_LOG_N_STEPS], ECDSA_BUILTIN_RATIO);

        require(

            ctx[MM_INITIAL_ECDSA_ADDR] <= ecdsaStopPtr &&

            ecdsaStopPtr <= ecdsaMaxStopPtr,

            "Invalid ecdsa stop_ptr");



        // Public memory.

        require(

            publicInput[OFFSET_N_PUBLIC_MEMORY_PAGES] >= 1 &&

            publicInput[OFFSET_N_PUBLIC_MEMORY_PAGES] < 100000,

            "Invalid number of memory pages.");

        ctx[MM_N_PUBLIC_MEM_PAGES] = publicInput[OFFSET_N_PUBLIC_MEMORY_PAGES];



        {

        // Compute the total number of public memory entries.

        uint256 n_public_memory_entries = 0;

        for (uint256 page = 0; page < ctx[MM_N_PUBLIC_MEM_PAGES]; page++) {

            uint256 n_page_entries = publicInput[getOffsetPageSize(page)];

            require(n_page_entries < 2**30, "Too many public memory entries in one page.");

            n_public_memory_entries += n_page_entries;

        }

        ctx[MM_N_PUBLIC_MEM_ENTRIES] = n_public_memory_entries;

        }



        uint256 expectedPublicInputLength = getPublicInputLength(ctx[MM_N_PUBLIC_MEM_PAGES]);

        require(

            expectedPublicInputLength == publicInput.length,

            "Public input length mismatch.");



        uint256 lmmPublicInputPtr = MM_PUBLIC_INPUT_PTR;

        assembly {

            // Set public input pointer to point at the first word of the public input

            // (skipping length word).

            mstore(add(ctx, mul(add(lmmPublicInputPtr, 1), 0x20)), add(publicInput, 0x20))

        }



        // Pedersen's shiftPoint values.

        ctx[MM_PEDERSEN__SHIFT_POINT_X] =

            0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804;

        ctx[MM_PEDERSEN__SHIFT_POINT_Y] =

            0x3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a;



        ctx[MM_RC16__PERM__PUBLIC_MEMORY_PROD] = 1;

        ctx[MM_ECDSA__SIG_CONFIG_ALPHA] = 1;

        ctx[MM_ECDSA__SIG_CONFIG_BETA] =

            0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89;

        ctx[MM_ECDSA__SIG_CONFIG_SHIFT_POINT_X] =

            0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804;

        ctx[MM_ECDSA__SIG_CONFIG_SHIFT_POINT_Y] =

            0x3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a;



    }



    function getPublicInputHash(uint256[] memory publicInput)

        internal pure

        returns (bytes32 publicInputHash) {



        // The initial seed consists of the first part of publicInput. Specifically, it does not

        // include the page products (which are only known later in the process, as they depend on

        // the values of z and alpha).

        uint256 nPages = publicInput[OFFSET_N_PUBLIC_MEMORY_PAGES];

        uint256 publicInputSizeForHash = 0x20 * (getOffsetPaddingCell(nPages) + 2);



        assembly {

            publicInputHash := keccak256(add(publicInput, 0x20), publicInputSizeForHash)

        }

    }



    function getCoefficients(uint256[] memory ctx)

        internal

        pure

        returns (uint256[N_COEFFICIENTS] memory coefficients)

    {

        uint256 offset = 0x20 + MM_COEFFICIENTS * 0x20;

        assembly {

            coefficients := add(ctx, offset)

        }

        return coefficients;

    }



    /*

      Computes the value of the public memory quotient:

        numerator / (denominator * padding)

      where:

        numerator = (z - (0 + alpha * 0))^S,

        denominator = \prod_i( z - (addr_i + alpha * value_i) ),

        padding = (z - (padding_addr + alpha * padding_value))^(S - N),

        N is the actual number of public memory cells,

        and S is the number of cells allocated for the public memory (which includes the padding).

    */

    function computePublicMemoryQuotient(uint256[] memory ctx) internal view returns (uint256) {

        uint256 nValues = ctx[MM_N_PUBLIC_MEM_ENTRIES];

        uint256 z = ctx[MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM];

        uint256 alpha = ctx[MM_MEMORY__MULTI_COLUMN_PERM__HASH_INTERACTION_ELM0];

        // The size that is allocated to the public memory.

        uint256 publicMemorySize = safeDiv(ctx[MM_TRACE_LENGTH], PUBLIC_MEMORY_STEP);



        require(nValues < 0x1000000, "Overflow protection failed.");

        require(nValues <= publicMemorySize, "Number of values of public memory is too large.");



        uint256 nPublicMemoryPages = ctx[MM_N_PUBLIC_MEM_PAGES];

        uint256 cumulativeProdsPtr =

            ctx[MM_PUBLIC_INPUT_PTR] + getOffsetPageProd(0, nPublicMemoryPages) * 0x20;

        uint256 denominator = computePublicMemoryProd(

            cumulativeProdsPtr, nPublicMemoryPages, K_MODULUS);



        // Compute address + alpha * value for the first address-value pair for padding.

        uint256 publicInputPtr = ctx[MM_PUBLIC_INPUT_PTR];

        uint256 paddingOffset = getOffsetPaddingCell(nPublicMemoryPages);

        uint256 paddingAddr;

        uint256 paddingValue;

        assembly {

            paddingAddr := mload(

                add(publicInputPtr, mul(0x20, paddingOffset)))

            paddingValue := mload(

                add(publicInputPtr, mul(0x20, add(paddingOffset, 1))))

        }

        uint256 hash_first_address_value = fadd(paddingAddr, fmul(paddingValue, alpha));



        // Pad the denominator with the shifted value of hash_first_address_value.

        uint256 denom_pad = fpow(

            fsub(z, hash_first_address_value),

            publicMemorySize - nValues);

        denominator = fmul(denominator, denom_pad);



        // Calculate the numerator.

        uint256 numerator = fpow(z, publicMemorySize);



        // Compute the final result: numerator * denominator^(-1).

        return fmul(numerator, inverse(denominator));

    }



    /*

      Computes the cumulative product of the public memory cells:

        \prod_i( z - (addr_i + alpha * value_i) ).



      publicMemoryPtr is an array of nValues pairs (address, value).

      z and alpha are the perm and hash interaction elements required to calculate the product.

    */

    function computePublicMemoryProd(

        uint256 cumulativeProdsPtr, uint256 nPublicMemoryPages, uint256 prime)

        internal pure returns (uint256 res)

    {

        assembly {

            let lastPtr := add(cumulativeProdsPtr, mul(nPublicMemoryPages, 0x20))

            res := 1

            for { let ptr := cumulativeProdsPtr } lt(ptr, lastPtr) { ptr := add(ptr, 0x20) } {

                res := mulmod(res, mload(ptr), prime)

            }

        }

    }



    /*

      Verifies that all the information on each public memory page (size, hash, prod, and possibly

      address) is consistent with z and alpha, by checking that the corresponding facts were

      registered on memoryPageFactRegistry.

    */

    function verifyMemoryPageFacts(uint256[] memory ctx) internal view {

        uint256 nPublicMemoryPages = ctx[MM_N_PUBLIC_MEM_PAGES];



        for (uint256 page = 0; page < nPublicMemoryPages; page++) {

            // Fetch page values from the public input (hash, product and size).

            uint256 memoryHashPtr = ctx[MM_PUBLIC_INPUT_PTR] + getOffsetPageHash(page) * 0x20;

            uint256 memoryHash;



            uint256 prodPtr = ctx[MM_PUBLIC_INPUT_PTR] +

                getOffsetPageProd(page, nPublicMemoryPages) * 0x20;

            uint256 prod;



            uint256 pageSizePtr = ctx[MM_PUBLIC_INPUT_PTR] + getOffsetPageSize(page) * 0x20;

            uint256 pageSize;



            assembly {

                pageSize := mload(pageSizePtr)

                prod := mload(prodPtr)

                memoryHash := mload(memoryHashPtr)

            }



            uint256 pageAddr = 0;

            if (page > 0) {

                uint256 pageAddrPtr = ctx[MM_PUBLIC_INPUT_PTR] + getOffsetPageAddr(page) * 0x20;

                assembly {

                    pageAddr := mload(pageAddrPtr)

                }

            }



            // Verify that a corresponding fact is registered attesting to the consistency of the page

            // information with z and alpha.

            bytes32 factHash = keccak256(

                abi.encodePacked(

                    page == 0 ? REGULAR_PAGE : CONTINUOUS_PAGE,

                    K_MODULUS,

                    pageSize,

                    /*z=*/ctx[MM_INTERACTION_ELEMENTS],

                    /*alpha=*/ctx[MM_INTERACTION_ELEMENTS + 1],

                    prod,

                    memoryHash,

                    pageAddr)

            );



            require(  // NOLINT: calls-loop.

                memoryPageFactRegistry.isValid(factHash), "Memory page fact was not registered.");

        }

    }



    /*

      Checks that the trace and the compostion agree at oodsPoint, assuming the prover provided us

      with the proper evaluations.



      Later, we will use boundery constraints to check that those evaluations are actully consistent

      with the commited trace and composition ploynomials.

    */

    function oodsConsistencyCheck(uint256[] memory ctx) internal view {

        verifyMemoryPageFacts(ctx);



        uint256 oodsPoint = ctx[MM_OODS_POINT];



        // The number of copies in the pedersen hash periodic columns is

        // nSteps / PEDERSEN_BUILTIN_RATIO / PEDERSEN_BUILTIN_REPETITIONS.

        uint256 nPedersenHashCopies = safeDiv(

            2 ** ctx[MM_LOG_N_STEPS],

            PEDERSEN_BUILTIN_RATIO * PEDERSEN_BUILTIN_REPETITIONS);

        uint256 zPointPowPedersen = fpow(oodsPoint, nPedersenHashCopies);



        ctx[MM_PERIODIC_COLUMN__PEDERSEN__POINTS__X] = pedersenPointsX.compute(zPointPowPedersen);

        ctx[MM_PERIODIC_COLUMN__PEDERSEN__POINTS__Y] = pedersenPointsY.compute(zPointPowPedersen);



        // The number of copies in the ECDSA signature periodic columns is

        // nSteps / ECDSA_BUILTIN_RATIO / ECDSA_BUILTIN_REPETITIONS.

        uint256 nEcdsaSignatureCopies = safeDiv(

            2 ** ctx[MM_LOG_N_STEPS],

            ECDSA_BUILTIN_RATIO * ECDSA_BUILTIN_REPETITIONS);

        uint256 zPointPowEcdsa = fpow(oodsPoint, nEcdsaSignatureCopies);



        ctx[MM_PERIODIC_COLUMN__ECDSA__GENERATOR_POINTS__X] = ecdsaPointsX.compute(zPointPowEcdsa);

        ctx[MM_PERIODIC_COLUMN__ECDSA__GENERATOR_POINTS__Y] = ecdsaPointsY.compute(zPointPowEcdsa);



        ctx[MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM] = ctx[MM_INTERACTION_ELEMENTS];

        ctx[MM_MEMORY__MULTI_COLUMN_PERM__HASH_INTERACTION_ELM0] = ctx[MM_INTERACTION_ELEMENTS + 1];

        ctx[MM_RC16__PERM__INTERACTION_ELM] = ctx[MM_INTERACTION_ELEMENTS + 2];



        uint256 public_memory_prod = computePublicMemoryQuotient(ctx);



        ctx[MM_MEMORY__MULTI_COLUMN_PERM__PERM__PUBLIC_MEMORY_PROD] = public_memory_prod;



        uint256 compositionFromTraceValue;

        address lconstraintPoly = address(constraintPoly);

        uint256 offset = 0x20 * (1 + MM_CONSTRAINT_POLY_ARGS_START);

        uint256 size = 0x20 *

            (MM_CONSTRAINT_POLY_ARGS_END - MM_CONSTRAINT_POLY_ARGS_START);

        assembly {

            // Call CpuConstraintPoly contract.

            let p := mload(0x40)

            if iszero(

                staticcall(

                    not(0),

                    lconstraintPoly,

                    add(ctx, offset),

                    size,

                    p,

                    0x20

                )

            ) {

                returndatacopy(0, 0, returndatasize)

                revert(0, returndatasize)

            }

            compositionFromTraceValue := mload(p)

        }



        uint256 claimedComposition = fadd(

            ctx[MM_OODS_VALUES + MASK_SIZE],

            fmul(oodsPoint, ctx[MM_OODS_VALUES + MASK_SIZE + 1])

        );



        require(

            compositionFromTraceValue == claimedComposition,

            "claimedComposition does not match trace"

        );

    }



    function safeDiv(uint256 numerator, uint256 denominator) internal pure returns (uint256) {

        require(denominator > 0, "The denominator must not be zero");

        require(numerator % denominator == 0, "The numerator is not divisible by the denominator.");

        return numerator / denominator;

    }

}

contract CpuFrilessVerifier is

    CpuVerifier,

    MerkleStatementVerifier,

    FriStatementVerifier

{

    constructor(

        address[] memory auxPolynomials,

        address oodsContract,

        address memoryPageFactRegistry_,

        address merkleStatementContractAddress,

        address friStatementContractAddress,

        uint256 numSecurityBits_,

        uint256 minProofOfWorkBits_

    )

        public

        MerkleStatementVerifier(merkleStatementContractAddress)

        FriStatementVerifier(friStatementContractAddress)

        CpuVerifier(

            auxPolynomials,

            oodsContract,

            memoryPageFactRegistry_,

            numSecurityBits_,

            minProofOfWorkBits_

        )

    {

        // solium-disable-previous-line no-empty-blocks

    }

}
