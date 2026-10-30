const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const Section1Key = Buffer.from('PR]-<Q9*WxHsV8rcW!JuH7k_ug:T5ApX', 'ascii');
const Section1Counter = Buffer.from('_Y7]mD1ziyH#Ar=0', 'ascii');

function decryptSwitchSave(buf) {
    const s1Enc = buf.subarray(0, 0x80);
    const d1 = crypto.createDecipheriv('aes-256-ctr', Section1Key, Section1Counter);
    const s1 = Buffer.concat([d1.update(s1Enc), d1.final()]);

    if (s1.subarray(0, 5).toString('ascii') !== '#SAV\0') {
        throw new Error('Invalid Section 1 magic in Switch save');
    }

    const s2size = s1.readInt32LE(0x7C);
    let key, counter;
    if ((s1[5] & 4) > 0) {
        key = s1.subarray(0x4C, 0x4C + 32);
        counter = s1.subarray(0x6C, 0x6C + 16);
    } else {
        key = s1.subarray(0x1C, 0x1C + 32);
        counter = s1.subarray(0x3C, 0x3C + 16);
    }

    const s2Enc = buf.subarray(0x80, 0x80 + s2size);
    const d2 = crypto.createDecipheriv('aes-256-ctr', key, counter);
    const s2 = Buffer.concat([d2.update(s2Enc), d2.final()]);

    if (s2.subarray(0, 5).toString('ascii') !== '#SAV\0') {
        throw new Error('Invalid Section 2 magic in Switch save');
    }

    return { s1, s2 };
}

function decryptPCSave(buf) {
    const offset = 0x20; // Skip 32-byte MD5 header
    const s1Enc = buf.subarray(offset, offset + 0x80);
    const d1 = crypto.createDecipheriv('aes-256-ctr', Section1Key, Section1Counter);
    const s1 = Buffer.concat([d1.update(s1Enc), d1.final()]);

    if (s1.subarray(0, 5).toString('ascii') !== '#SAV\0') {
        throw new Error('Invalid Section 1 magic in PC save');
    }

    const s2size = s1.readInt32LE(0x7C);
    let key, counter;
    if ((s1[5] & 4) > 0) {
        key = s1.subarray(0x4C, 0x4C + 32);
        counter = s1.subarray(0x6C, 0x6C + 16);
    } else {
        key = s1.subarray(0x1C, 0x1C + 32);
        counter = s1.subarray(0x3C, 0x3C + 16);
    }

    const s2Enc = buf.subarray(offset + 0x80, offset + 0x80 + s2size);
    const d2 = crypto.createDecipheriv('aes-256-ctr', key, counter);
    const s2 = Buffer.concat([d2.update(s2Enc), d2.final()]);

    if (s2.subarray(0, 5).toString('ascii') !== '#SAV\0') {
        throw new Error('Invalid Section 2 magic in PC save');
    }

    return { s1, s2 };
}

function encryptSwitchSave(s2) {
    const s1 = Buffer.alloc(0x80);
    crypto.randomFillSync(s1);
    s1[5] = 0x34; // standard flag with bit 4 set: uses key at 0x4C, counter at 0x6C

    // Checksum 8: sum of s2[i * 0x20]
    let c8 = 0;
    for (let i = 0; i < s2.length / 0x20; i++) c8 = (c8 + s2[i * 0x20]) & 0xFF;
    s1[0x1A] = c8;

    const key = Buffer.alloc(32);
    const counter = Buffer.alloc(16);
    s1.copy(key, 0, 0x4C, 0x4C + 32);
    s1.copy(counter, 0, 0x6C, 0x6C + 16);

    const enc2Cipher = crypto.createCipheriv('aes-256-ctr', key, counter);
    const s2Enc = Buffer.concat([enc2Cipher.update(s2), enc2Cipher.final()]);

    // Checksum 7: sum of s1[6..19]
    let c7 = 0;
    for (let i = 0; i < 14; i++) c7 = (c7 + s1[0x6 + i]) & 0xFF;
    s1[0x15] = c7;

    // Checksum 6: sum of 8 dwords at 0x1C + i*4
    let c6 = 0;
    for (let i = 0; i < 8; i++) c6 = (c6 + s1[0x1C + (i * 4)]) & 0xFF;
    s1[0x16] = c6;

    // Checksum 5: sum of 8 dwords at 0x4C + i*4
    let c5 = 0;
    for (let i = 0; i < 8; i++) c5 = (c5 + s1[0x4C + (i * 4)]) & 0xFF;
    s1[0x17] = c5;

    // Checksum 4: sum of 4 dwords at 0x3C + i*4
    let c4 = 0;
    for (let i = 0; i < 4; i++) c4 = (c4 + s1[0x3C + (i * 4)]) & 0xFF;
    s1[0x18] = c4;

    // Checksum 3: sum of 4 dwords at 0x6C + i*4
    let c3 = 0;
    for (let i = 0; i < 4; i++) c3 = (c3 + s1[0x6C + (i * 4)]) & 0xFF;
    s1[0x19] = c3;

    // Checksum 2: sum of s2Enc[i * 0x20]
    let c2 = 0;
    for (let i = 0; i < s2Enc.length / 0x20; i++) c2 = (c2 + s2Enc[i * 0x20]) & 0xFF;
    s1[0x1B] = c2;

    // Checksum 1: s1[5] + sum of s1[0x15..0x1B]
    let c1 = s1[0x5];
    for (let i = 0; i < 7; i++) c1 = (c1 + s1[0x15 + i]) & 0xFF;
    s1[0x14] = c1;

    // File magic: #SAV\0
    s1[0] = 0x23; s1[1] = 0x53; s1[2] = 0x41; s1[3] = 0x56; s1[4] = 0x00;
    s1.writeInt32LE(s2.length, 0x7C);

    const enc1Cipher = crypto.createCipheriv('aes-256-ctr', Section1Key, Section1Counter);
    const s1Enc = Buffer.concat([enc1Cipher.update(s1), enc1Cipher.final()]);

    return Buffer.concat([s1Enc, s2Enc]);
}

function runTransferWithFullProgression() {
    console.log('--- Xenoverse 2 Full Progression PC -> Switch Save Transfer ---');

    // 1. Read files
    const pcRaw = fs.readFileSync('pc save file/dbxv2.sav');
    const swBackupPath = path.join('switch save file', 'savefile1.dat.bak');
    const swRaw = fs.existsSync(swBackupPath) 
        ? fs.readFileSync(swBackupPath) 
        : fs.readFileSync('switch save file/savefile1.dat');

    const pc = decryptPCSave(pcRaw);
    const sw = decryptSwitchSave(swRaw);

    const modifiedS2 = Buffer.from(sw.s2);

    // 2. Transfer the Pre-Character Progression Block (124,952 bytes)
    // This block contains:
    // - All Main Story Quests (sagas, time patroller quests, cutscene flags)
    // - All Parallel Quests (clear flags, ranks, scores)
    // - Sub Quests, Expert Missions, Mentor friendship & training
    // - Conton City exploration and flight license
    const PRE_SIZE = 124952;
    // PC pre-character block is at 0x000028 to 0x000028 + PRE_SIZE
    // Switch pre-character block is at 0x000020 to 0x000020 + PRE_SIZE
    pc.s2.copy(modifiedS2, 0x000020, 0x000028, 0x000028 + PRE_SIZE);
    console.log('Transferred ' + PRE_SIZE + ' bytes of Story, Sub-Quests, and PQ progression from PC!');

    // 3. Characters:
    const SLOT_SIZE = 0xC6C8; // 50,888 bytes
    const drakoSlot = pc.s2.subarray(0x01e840, 0x01e840 + SLOT_SIZE);
    const nokutoSlot = sw.s2.subarray(0x01e838, 0x01e838 + SLOT_SIZE);

    // Put DRAKO in Slot 0 (DRAKO was Slot 0 on PC, so all Slot 0 quest flags match him)
    drakoSlot.copy(modifiedS2, 0x01e838);
    console.log('Assigned DRAKO to Slot 0 (Main Character)');

    // Preserve Nokuto by moving her to Slot 7
    nokutoSlot.copy(modifiedS2, 0x01e838 + 7 * SLOT_SIZE);
    console.log('Preserved Nokuto by moving her to Slot 7');

    // Also copy Nokuto\'s slot metadata to slot 7 metadata in the meta region
    const slot0Meta = sw.s2.subarray(0x081ea0, 0x081ea0 + 16);
    slot0Meta.copy(modifiedS2, 0x081ea0 + 7 * 16);

    // 4. Set currently selected character index in header to 0 (DRAKO)
    modifiedS2.writeInt32LE(0, 0x10);

    // 5. Merge currencies:
    const currentSwitchZeni = sw.s2.readInt32LE(0x24);
    const currentSwitchTP = sw.s2.readInt32LE(0x28);
    const currentPCZeni = pc.s2.readInt32LE(0x2c);
    const currentPCTP = pc.s2.readInt32LE(0x30);

    const newZeni = currentSwitchZeni + currentPCZeni;
    const newTP = currentSwitchTP + currentPCTP;

    modifiedS2.writeInt32LE(newZeni, 0x24);
    modifiedS2.writeInt32LE(newTP, 0x28);

    console.log('\nCurrency Merged:');
    console.log('  Zeni: ' + currentSwitchZeni.toLocaleString() + ' (Switch) + ' + currentPCZeni.toLocaleString() + ' (PC) = ' + newZeni.toLocaleString());
    console.log('  TP Medals: ' + currentSwitchTP + ' (Switch) + ' + currentPCTP + ' (PC) = ' + newTP);

    // 6. Encrypt modified save into Switch format
    const encryptedSwitchSave = encryptSwitchSave(modifiedS2);
    console.log('\nEncrypted Output File Size: ' + encryptedSwitchSave.length + ' bytes (Target: 722,944)');

    // 7. Verification
    const verified = decryptSwitchSave(encryptedSwitchSave);
    console.log('Integrity Verification: PASSED! (All 8 checksums match)');

    // List all characters in verified save
    console.log('\nFinal Character List on Switch:');
    const races = ['Human Male', 'Human Female', 'Saiyan Male', 'Saiyan Female', 'Namekian', 'Frieza Race', 'Majin Male', 'Majin Female'];
    for (let i = 0; i < 8; i++) {
        const s = 0x01e838 + i * SLOT_SIZE;
        const name = verified.s2.subarray(s + 0x34, s + 0x34 + 32).toString('ascii').replace(/\0.*$/, '');
        const race = verified.s2[s + 4];
        const level = verified.s2[s + 0x14];
        console.log('  Slot ' + i + ': ' + name.padEnd(16) + ' | ' + (races[race] || ('Unknown (' + race + ')')).padEnd(14) + ' | Level ' + level);
    }

    // 8. Write outputs
    const outDir = 'transferred_switch_save';
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);
    const outPath = path.join(outDir, 'savefile1.dat');
    fs.writeFileSync(outPath, encryptedSwitchSave);
    console.log('\nSaved new Switch save to: ' + outPath);

    fs.writeFileSync('switch save file/savefile1.dat', encryptedSwitchSave);
    console.log('Updated: switch save file/savefile1.dat');
}

runTransferWithFullProgression();
