--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Section Header Block (SHB): magic, version, section length, options.
--  SHB also decides the byte order for the rest of its section.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.SHB is

   type SHB_View is record
      Order          : Byte_Order;
      Swapped        : Boolean;
      Major          : Unsigned_16;
      Minor          : Unsigned_16;
      Section_Length : Integer_64;
      Body_First     : Buffer_Index;
      Body_Last      : Natural;
      Total_Length   : Natural;
      Valid          : Boolean;
   end record;

   --  Detect byte order from the byte-order magic at Pos + 8, then fully
   --  validate the SHB envelope. Accepts both LE and BE files.
   procedure Parse_SHB
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      View  : out SHB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last,
     Post => (if Error = None
              then Next > Pos
                and then Next - 1 <= Buf'Last
                and then View.Valid);

   --  Validate magic + version only (cheap pre-check for sniffing).
   function Looks_Like_SHB
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Boolean
   with
     Pre => Pos >= Buf'First and then Pos <= Buf'Last;

   SHB_Hardware_Opt : constant Unsigned_16 := 2;
   SHB_OS_Opt       : constant Unsigned_16 := 3;
   SHB_Userappl_Opt : constant Unsigned_16 := 4;

   --  Locate an option inside a parsed SHB view (comment = 1, etc.).
   procedure Get_Option
     (Buf   : Byte_Buffer;
      View  : SHB_View;
      Order : Byte_Order;
      Code  : Unsigned_16;
      First : out Natural;
      Last  : out Natural;
      Found : out Boolean);

end Pcapng_In_Ada.SHB;
