'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const ENGINE = require('./engine.js');

test('parseUrl: bare domain tanpa protokol/www tetap terurai', () => {
  const p = ENGINE.parseUrl('google.com');
  assert.equal(p.host, 'google.com');
  assert.equal(p.regDomain, 'google.com');
  assert.equal(p.sld, 'google');
  assert.equal(p.hasProtocol, false);
  assert.equal(p.parseError, false);
});

test('parseUrl: www.facebook.com/login', () => {
  const p = ENGINE.parseUrl('www.facebook.com/login');
  assert.equal(p.host, 'www.facebook.com');
  assert.equal(p.regDomain, 'facebook.com');
  assert.equal(p.sld, 'facebook');
  assert.equal(p.path, '/login');
});

test('parseUrl: ccTLD dua tingkat (bni.co.id)', () => {
  const p = ENGINE.parseUrl('id.bni.co.id');
  assert.equal(p.regDomain, 'bni.co.id');
  assert.equal(p.sld, 'bni');
  assert.equal(p.tld, '.id');
});

test('parseUrl: URL berprotokol', () => {
  const p = ENGINE.parseUrl('https://google.com/a?b=1');
  assert.equal(p.protocol, 'https:');
  assert.equal(p.hasProtocol, true);
  assert.equal(p.path, '/a?b=1');
});

test('parseUrl: IP literal', () => {
  const p = ENGINE.parseUrl('192.168.1.10/login');
  assert.equal(p.isIp, true);
});

test('domain bersih → CLEAN', () => {
  for (const url of ['google.com', 'https://google.com', 'paypal.com', 'tokopedia.com', 'grabfood.com', 'login.paypal.com', 'login.bni.co.id', 'id.bni.co.id', 'www.facebook.com/login']) {
    const r = ENGINE.scanUrl(url);
    assert.equal(r.grade.verdict, 'CLEAN', `${url} harus CLEAN, dapat ${r.grade.verdict} (${r.score})`);
  }
});

test('typosquat/homoglyph → DANGER', () => {
  const cases = ['paypa1.com', 'paypa1-secure-login.com', 'secure-paypal.xyz', 'paypal.evil.top', 'paypa1-secure-login.com/verify/account'];
  for (const url of cases) {
    const r = ENGINE.scanUrl(url);
    assert.equal(r.grade.verdict, 'DANGER', `${url} harus DANGER, dapat ${r.grade.verdict} (${r.score})`);
  }
});

test('brand + kata mencurigakan → DANGER', () => {
  for (const url of ['bni-login.com', 'dana-rewards.online', 'amaz0n-prime.com', 'bankmandiri-login.com']) {
    const r = ENGINE.scanUrl(url);
    assert.equal(r.grade.verdict, 'DANGER', `${url} harus DANGER, dapat ${r.grade.verdict} (${r.score})`);
  }
});

test('IP literal → DANGER', () => {
  const r = ENGINE.scanUrl('192.168.1.10/login');
  assert.equal(r.grade.verdict, 'DANGER');
});

test('shortener → minimal WARN', () => {
  const r = ENGINE.scanUrl('bit.ly/3xYz9Q');
  assert.ok(r.grade.verdict !== 'CLEAN');
});

test('punycode → DANGER', () => {
  const r = ENGINE.scanUrl('xn--fpaypal-1234.com');
  assert.equal(r.grade.verdict, 'DANGER');
});

test('levenshtein: nilai dasar', () => {
  assert.equal(ENGINE.levenshtein('paypal', 'paypal'), 0);
  assert.equal(ENGINE.levenshtein('paypa1', 'paypal'), 1);
  assert.equal(ENGINE.levenshtein('paypal', 'paypallogin'), 5);
});

test('gradeScore ambang', () => {
  assert.equal(ENGINE.gradeScore(0).verdict, 'CLEAN');
  assert.equal(ENGINE.gradeScore(19).verdict, 'CLEAN');
  assert.equal(ENGINE.gradeScore(20).verdict, 'WARN');
  assert.equal(ENGINE.gradeScore(49).verdict, 'WARN');
  assert.equal(ENGINE.gradeScore(50).verdict, 'DANGER');
});

test('skor tidak melebihi 100', () => {
  const r = ENGINE.scanUrl('http://bankmandiri-login.com/otp/verify/secure/account/login/confirm?x=1');
  assert.ok(r.score <= 100);
});