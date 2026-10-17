--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Root package for the Pcapng_In_Ada library.
--  Common scalar types, block-type codes from the IETF pcapng draft,
--  and the shared error model (single Result pattern, no exceptions).

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;

package Pcapng_In_Ada is

   --  Single-byte buffer used across the whole library. The index
   --  subtype stops Max_Block_Size short of Positive'Last so that
   --  Pos + Total can never overflow: Pos <= Buffer_Index'Last and
   --  Total <= Max_Block_Size always fit in Integer. Buffers up to
   --  ~2 GiB minus one block remain addressable, far beyond capture
   --  needs, and Positive interop keeps Stream_Element conversion easy.
   Max_Block_Size : constant Natural := 16#1000000#;

   subtype Buffer_Index is
     Positive range 1 .. Positive'Last - Max_Block_Size;

   type Byte_Buffer is array (Buffer_Index range <>) of Unsigned_8;

   type Byte_Order is (Little_Endian, Big_Endian);

   --  IETF pcapng block type codes (Section 10.1 of the draft).
   SHB_Type : constant Unsigned_32 := 16#0A0D_0D0A#;
   IDB_Type : constant Unsigned_32 := 16#0000_0001#;
   SPB_Type : constant Unsigned_32 := 16#0000_0003#;
   NRB_Type : constant Unsigned_32 := 16#0000_0004#;
   ISB_Type : constant Unsigned_32 := 16#0000_0005#;
   EPB_Type : constant Unsigned_32 := 16#0000_0006#;
   CB1_Type : constant Unsigned_32 := 16#0000_0BAD#;
   CB2_Type : constant Unsigned_32 := 16#4000_0BAD#;

   Byte_Order_Magic : constant Unsigned_32 := 16#1A2B_3C4D#;
   SHB_Version_Major : constant Unsigned_16 := 1;
   SHB_Version_Minor : constant Unsigned_16 := 0;

   --  Minimum sizes in bytes (header + trailer included where noted).
   Block_Header_Size   : constant Positive := 8;
   Block_Trailer_Size  : constant Positive := 4;
   Min_Block_Size      : constant Positive := 12;
   SHB_Min_Size        : constant Positive := 28;
   IDB_Min_Size        : constant Positive := 20;
   EPB_Min_Size        : constant Positive := 32;
   SPB_Min_Size        : constant Positive := 16;

   type Error_Kind is
     (None,
      Truncated,
      Bad_Magic,
      Bad_Version,
      Bad_Length,
      Bad_Trailer,
      Bad_Option,
      Unsupported,
      No_Space);

   type Block_Kind is
     (Kind_SHB,
      Kind_IDB,
      Kind_SPB,
      Kind_NRB,
      Kind_ISB,
      Kind_EPB,
      Kind_Custom,
      Kind_Unknown);

   function Block_Kind_Of (Block_Type : Unsigned_32) return Block_Kind is
     (case Block_Type is
        when SHB_Type => Kind_SHB,
        when IDB_Type => Kind_IDB,
        when SPB_Type => Kind_SPB,
        when NRB_Type => Kind_NRB,
        when ISB_Type => Kind_ISB,
        when EPB_Type => Kind_EPB,
        when CB1_Type | CB2_Type => Kind_Custom,
        when others  => Kind_Unknown)
   with Inline;

   function Is_Known (Block_Type : Unsigned_32) return Boolean is
     (Block_Kind_Of (Block_Type) /= Kind_Unknown)
   with Inline;

end Pcapng_In_Ada;
