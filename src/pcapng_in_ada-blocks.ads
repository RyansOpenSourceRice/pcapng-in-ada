--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Generic block framing: parse and validate the 12-byte envelope
--  (type + total-length ... body ... trailing total-length).

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;

package Pcapng_In_Ada.Blocks is

   type Block_Header is record
      Block_Type   : Unsigned_32;
      Total_Length : Natural;
      Swapped      : Boolean;
   end record;

   --  Parse the envelope at position Pos (1-based into Buf).
   --  On success Error = None and Next gives the offset of the next block.
   procedure Parse_Header
     (Buf          : Byte_Buffer;
      Pos : Buffer_Index;
      Order        : Byte_Order;
      Header       : out Block_Header;
      Next         : out Natural;
      Error        : out Error_Kind)
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last,
     Post => (if Error = None
              then Next = Pos + Header.Total_Length
                and then Next - 1 <= Buf'Last
                and then Header.Total_Length >= Min_Block_Size
                and then Header.Total_Length <= Max_Block_Size
                and then Header.Total_Length <= Buf'Last - Pos + 1);

   --  Validate that a claimed total length fits inside Buf from Pos.
   function Length_Fits
     (Buf : Byte_Buffer; Pos : Buffer_Index; Total : Natural) return Boolean
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last,
     Post => (if Length_Fits'Result
              then Total >= Min_Block_Size
                and then Total <= Max_Block_Size
                and then Total <= Buf'Last - Pos + 1);

   --  Encode an 8-byte header + 4-byte trailer around a body. Caller
   --  supplies Body_Len; this unit writes leading/trailing lengths.
   procedure Encode_Envelope
     (Buf        : in out Byte_Buffer;
      Pos : Buffer_Index;
      Block_Type : Unsigned_32;
      Body_Len   : Natural;
      Order      : Byte_Order;
      Next       : out Natural;
      Error      : out Error_Kind)
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last
       and then Body_Len <= Max_Block_Size,
     Post => (if Error = None
              then Next = Pos + Body_Len + Block_Header_Size
                             + Block_Trailer_Size
                and then Next - 1 <= Buf'Last);

end Pcapng_In_Ada.Blocks;
