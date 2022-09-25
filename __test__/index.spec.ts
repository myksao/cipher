import test from 'ava'

import { Cipher } from '../index'

test('cipher', (t) => {
  const cipher = new Cipher([
    214, 106, 249, 58, 182, 101,  64,  58,
     87,  73,   0, 48, 221,  29, 115, 229,
    235,  34, 143, 79, 132, 233,  99, 191,
     22, 126,  85, 23,  99,  86, 180,  32
  ], [
    158,  19,   3, 31, 190,
    158, 135, 113, 87,  81,
     62, 110
  ]);
  t.log(t.deepEqual(cipher.encrypt('hello world'),  [
    218, 220, 165, 242, 230, 154, 144,
    171, 160,  95,  50,  87,  53,  42,
     85,  55, 127,  81,  78, 179, 198,
    234, 135,  39, 200,  56,  54
  ], 'Encrypted'));
  t.log(t.deepEqual(cipher.decrypt([
    218, 220, 165, 242, 230, 154, 144,
    171, 160,  95,  50,  87,  53,  42,
     85,  55, 127,  81,  78, 179, 198,
    234, 135,  39, 200,  56,  54
  ]), "hello world", 'Decrypted'));
  t.pass();
})
