pragma circom 2.0.2;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";
include "../../node_modules/circomlib/circuits/eddsamimc.circom";


template Main(n) {
    signal input paths_to_root[n-1];

    signal input current_state;
    signal input new_state;
    
    signal input pubkey[2][1];
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input owner;
    signal input tokenId;
    signal input secret;
    signal input stealthAddrBytes;
    
    signal stealthBytes;

    var i;
    
    component stealth = MiMCSponge(3, 220, 1);
    stealth.ins[0] <== owner;
    stealth.ins[1] <== tokenId;
    stealth.ins[2] <== secret;
    stealth.k <== 0;
    log(stealth.outs[0]);
    
    stealthBytes <== stealth.outs[0];
    log(stealthBytes);
    
    stealthAddrBytes === stealthBytes;
    
      
    component old_hash = MultiMiMC7(3,91);
    old_hash.in[0] <== 0;
    old_hash.in[1] <== 0;
    old_hash.in[2] <== 0;
    old_hash.k <== 0;
    log(old_hash.out);
    
    component old_merkle[n-1];
    old_merkle[0] = MultiMiMC7(2,91);
    old_merkle[0].in[0] <== old_hash.out;
    old_merkle[0].in[1] <== paths_to_root[0];
    old_merkle[0].k <== 0;
    log(old_merkle[i-1].out);
    
    
    for (i=1; i<n-1; i++){
        old_merkle[i] = MultiMiMC7(2,91);
        old_merkle[i].in[0] <== old_merkle[i-1].out;
        old_merkle[i].in[1] <== paths_to_root[i-1];
        old_merkle[i].k <== 0;
    }
    
    log(current_state);
    log(old_merkle[n-2].out);
    
    current_state === old_merkle[n-2].out;
    
    
    component verifier = EdDSAMiMCVerifier();   
    verifier.enabled <== 1;
    verifier.Ax <== pubkey[0][0];
    verifier.Ay <== pubkey[1][0];
    verifier.R8x <== R8x;
    verifier.R8y <== R8y;
    verifier.S <== S;
    verifier.M <== old_hash.out;

        
    component new_merkle[n-1];
    new_merkle[0] = MultiMiMC7(2,91);
    new_merkle[0].in[0] <== stealthBytes;
    new_merkle[0].in[1] <== paths_to_root[0];
    new_merkle[0].k <== 0;
    for (i=1; i<n-1; i++){
        new_merkle[i] = MultiMiMC7(2,91);
        new_merkle[i].in[0] <== new_merkle[i-1].out;
        new_merkle[i].in[1] <== paths_to_root[i-1];
        new_merkle[i].k <== 0;
    }

    log(new_merkle[n-2].out);
    log(new_state);
    new_state === new_merkle[n-2].out;
}

component main {public [current_state, new_state, pubkey, R8x, R8y, S, stealthAddrBytes]} = Main(20);
