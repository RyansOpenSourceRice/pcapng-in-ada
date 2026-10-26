--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

with AUnit; use AUnit;
with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Cases; use AUnit.Test_Cases;
with AUnit.Test_Suites;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Blocks;
with Pcapng_In_Ada.SHB;
with Pcapng_In_Ada.Packet;
with Pcapng_In_Ada.Reader;
with Pcapng_In_Ada.Writer;

package body Pcapng_Tests.Malformed_Suite is

   type Test is new Test_Cases.Test_Case with null record;

   overriding function Name (T : Test) return Message_String;
   overriding procedure Register_Tests (T : in out Test);

   procedure T_Trunc_SHB (T : in out Test_Cases.Test_Case'Class);
   procedure T_Trailer (T : in out Test_Cases.Test_Case'Class);
   procedure T_Bad_Magic (T : in out Test_Cases.Test_Case'Class);
   procedure T_Unknown_Skip (T : in out Test_Cases.Test_Case'Class);
   procedure T_Caplen_Lt_Origlen (T : in out Test_Cases.Test_Case'Class);
   procedure T_Cut_Mid_Payload (T : in out Test_Cases.Test_Case'Class);

   overriding function Name (T : Test) return Message_String is
   begin
      pragma Unreferenced (T);
      return Format ("Malformed");
   end Name;

   overriding procedure Register_Tests (T : in out Test) is
   begin
      Registration.Register_Routine
        (T, T_Trunc_SHB'Access, "truncated shb -> Truncated");
      Registration.Register_Routine
        (T, T_Trailer'Access, "trailer mismatch -> Bad_Trailer");
      Registration.Register_Routine
        (T, T_Bad_Magic'Access, "bad magic rejected");
      Registration.Register_Routine
        (T, T_Unknown_Skip'Access, "unknown skipped, walk continues");
      Registration.Register_Routine
        (T, T_Caplen_Lt_Origlen'Access, "caplen < origlen is normal");
      Registration.Register_Routine
        (T, T_Cut_Mid_Payload'Access, "cut mid-payload -> Truncated");
   end Register_Tests;

   procedure T_Trunc_SHB (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf : Byte_Buffer (1 .. 10) := [others => 0];
      V   : SHB.SHB_View;
      Nx  : Natural;
      Er  : Error_Kind;
   begin
      SHB.Parse_SHB (Buf, Buf'First, V, Nx, Er);
      Assert (Er = Truncated, "truncated shb -> Truncated");
   end T_Trunc_SHB;

   procedure T_Trailer (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf   : Byte_Buffer (1 .. 64) := [others => 0];
      Last  : Natural := Buf'First - 1;
      Error : Error_Kind;
   begin
      Writer.Append_SHB (Buf, Last, Error);
      Assert (Error = None, "setup shb");
      Buf (Last - 1) := 16#FF#;
      declare
         Hdr : Blocks.Block_Header;
         Nx  : Natural;
         Er  : Error_Kind;
      begin
         Blocks.Parse_Header (Buf, Buf'First, Little_Endian, Hdr, Nx, Er);
         Assert (Er = Bad_Trailer, "trailer mismatch -> Bad_Trailer");
      end;
   end T_Trailer;

   procedure T_Bad_Magic (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf : Byte_Buffer (1 .. 28) := [others => 16#AA#];
      V   : SHB.SHB_View;
      Nx  : Natural;
      Er  : Error_Kind;
   begin
      SHB.Parse_SHB (Buf, Buf'First, V, Nx, Er);
      Assert (Er = Bad_Magic or else Er = Bad_Length or else Er = Truncated,
              "bad magic rejected");
   end T_Bad_Magic;

   procedure T_Unknown_Skip (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf   : Byte_Buffer (1 .. 256) := [others => 0];
      Last  : Natural := Buf'First - 1;
      Error : Error_Kind;
      Cur   : Reader.Cursor;
      Curr  : Reader.Current_Block;
      Seen_Unknown : Boolean := False;
      Count : Natural := 0;
   begin
      Writer.Append_SHB (Buf, Last, Error);
      Buf (Last + 1) := 16#78#;
      Buf (Last + 2) := 16#56#;
      Buf (Last + 3) := 16#34#;
      Buf (Last + 4) := 16#12#;
      Buf (Last + 5) := 12;
      Buf (Last + 6) := 0;
      Buf (Last + 7) := 0;
      Buf (Last + 8) := 0;
      Buf (Last + 9) := 12;
      Buf (Last + 10) := 0;
      Buf (Last + 11) := 0;
      Buf (Last + 12) := 0;
      Last := Last + 12;
      Writer.Append_IDB (Buf, Last, Error => Error);

      Cur := Reader.First (Buf'First);
      for I in 1 .. 6 loop
         Reader.Next (Buf (Buf'First .. Last), Cur, Curr);
         exit when Curr.Error /= None;
         Count := Count + 1;
         if Curr.Kind = Kind_Unknown then
            Seen_Unknown := True;
         end if;
         exit when Cur.At_End;
      end loop;
      Assert (Count = 3 and Seen_Unknown, "unknown skipped, 3 blocks");
   end T_Unknown_Skip;

   procedure T_Caplen_Lt_Origlen (T : in out Test_Cases.Test_Case'Class) is
      --  Snaplen-truncated payload: wire holds fewer bytes than the
      --  on-the-wire length. This is NORMAL (not an error).
      pragma Unreferenced (T);
      Buf   : Byte_Buffer (1 .. 256) := [others => 0];
      Last  : Natural := Buf'First - 1;
      Error : Error_Kind;
      Data  : Byte_Buffer (1 .. 10) := [others => 16#AB#];
      EPB_Start : Natural;
      View  : Packet.EPB_View;
      Nx    : Natural;
      Er    : Error_Kind;
   begin
      Writer.Append_SHB (Buf, Last, Error);
      Writer.Append_IDB (Buf, Last, Error => Error);
      EPB_Start := Last + 1;
      Writer.Append_EPB (Buf, Last, 0, 42, Data, Error);
      Assert (Error = None, "setup epb");
      --  Patch origlen (offset +24, LE) to 1_500 > caplen 10.
      Buf (EPB_Start + 24) := 16#DC#;
      Buf (EPB_Start + 25) := 16#05#;
      Buf (EPB_Start + 26) := 0;
      Buf (EPB_Start + 27) := 0;
      Packet.Parse_EPB (Buf (Buf'First .. Last), EPB_Start,
                        Little_Endian, View, Nx, Er);
      Assert (Er = None and then View.Valid,
              "caplen < origlen parses");
      Assert (View.Cap_Len = 10 and then View.Orig_Len = 1_500,
              "caplen/origlen preserved");
      Assert (View.Data_Last - View.Data_First + 1 = 10,
              "data span is caplen");
   end T_Caplen_Lt_Origlen;

   procedure T_Cut_Mid_Payload (T : in out Test_Cases.Test_Case'Class) is
      --  A slice ending inside an EPB payload is Truncated, never a raise.
      pragma Unreferenced (T);
      Buf   : Byte_Buffer (1 .. 256) := [others => 0];
      Last  : Natural := Buf'First - 1;
      Error : Error_Kind;
      Data  : Byte_Buffer (1 .. 64) := [others => 16#CD#];
      View  : Packet.EPB_View;
      Nx    : Natural;
      Er    : Error_Kind;
   begin
      Writer.Append_SHB (Buf, Last, Error);
      Writer.Append_IDB (Buf, Last, Error => Error);
      Writer.Append_EPB (Buf, Last, 0, 7, Data, Error);
      Assert (Error = None, "setup epb");
      Packet.Parse_EPB (Buf (Buf'First .. Last - 10), Buf'First + 48,
                        Little_Endian, View, Nx, Er);
      Assert (Er = Truncated, "cut mid-payload -> Truncated");
   end T_Cut_Mid_Payload;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      use AUnit.Test_Suites;
      S : constant Access_Test_Suite := New_Suite;
   begin
      S.Add_Test (new Test);
      return S;
   end Suite;

end Pcapng_Tests.Malformed_Suite;
