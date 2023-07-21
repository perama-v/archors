## InterpretedTrace specification

Details for a relatable data format that can be produced from an EIP-3155 trace.

> Note: This is a draft to test how useful a transaction trace can be made without ancillary data.

This data structure may be used to quickly evaluate "what a transaction is doing"

## Abstract

A specification for a data format that summarises what a transaction is doing. The
data is produced by a pure function with an EIP-3155 trace as an input.

## Motivation

Transaction logs show select important data, but exclude many details. Transaction
traces contain all data, but include many meaningless details.

This format seeks to filter important information from a transaction trace. That is,
include things like CALL, and the context surrounding the call and exclude things like ADD.

## Table of Contents


## Overview

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in RFC 2119 and RFC 8174.

### General Structure

TODO