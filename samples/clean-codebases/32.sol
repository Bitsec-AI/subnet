pragma solidity 0.5.15;

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
