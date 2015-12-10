# PBKDF2 Password Encoder for Spring [![build status](https://travis-ci.org/slave13043712/spring-pbkdf2-password-encoder.svg?branch=master)](https://travis-ci.org/slave13043712/spring-pbkdf2-password-encoder)

## Overview
This project provides Spring-compatible password encoder that uses PBKDF2 (Password-Based Key Derivation Function).

## Motivation
[OWASP](https://www.owasp.org/) suggests using PBKDF2 when FIPS certification or enterprise support on many platforms is required. Unfortunately **spring-security** provides only BCrypt password encoder.

## JRE/JDK Version
This password encoder uses PBKDF2WithHmacSHA512 algorithm to generate derived key. This algorithm is supported only by Java 8+ (see [this guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider) for more details).
