--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

with AUnit; use AUnit;
with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Cases; use AUnit.Test_Cases;
with AUnit.Test_Suites;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Writer;
with Pcapng_In_Ada.Reader;
with Pcapng_In_Ada.Packet;

package body Pcapng_Tests.Reader_Suite is

   type Test is new Test_Cases.Test_Case with null record;

   overriding function Name (T : Test) return Message_String;
   overriding procedure Register_Tests (T : in out Test);

   procedure Test_Write_Read (T : in out Test_Cases.Test_Case'Class);
   procedure Test_Payload_Echo (T : in out Test_Cases.Test_Case'Class);

   overriding function Name (T : Test) return Message_String is
   begin
      pragma Unreferenced (T);
      return Format ("Reader");
   end Name;

   overriding procedure Register_Tests (T : in out Test) is
   begin
      Registration.Register_Routine
        (T, Test_Write_Read'Access, "write shb/idb/epbx2, walk 4 blocks");
      Registration.Register_Routine
        (T, Test_Payload_Echo'Access, "epb payload echo");
   end Register_Tests;

   procedure Test_Write_Read (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf   : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last  : Natural := Buf'First - 1;
      Error : Error_Kind;
      Data  : Byte_Buffer (1 .. 14) :=
        [16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#,
         16#08#, 16#00#];
      Cur   : Reader.Cursor := Reader.First (Buf'First);
      Curr  : Reader.Current_Block;
      Count : Natural := 0;
   begin
      Writer.Append_SHB (Buf (1 .. Buf'Last), Last, Error);
      Assert (Error = None, "write shb");
      Writer.Append_IDB (Buf (1 .. Buf'Last), Last, Error => Error);
      Assert (Error = None, "write idb");
      Writer.Append_EPB
        (Buf (1 .. Buf'Last), Last, 0, 1_700_000_000_000_000, Data, Error);
      Assert (Error = None, "write epb#1");
      Writer.Append_EPB
        (Buf (1 .. Buf'Last), Last, 0, 1_700_000_000_000_001, Data, Error);
      Assert (Error = None, "write epb#2");

      declare
         Img : Byte_Buffer renames Buf;
      begin
         Cur := Reader.First (Img'First);
         for I in 1 .. 6 loop
            Reader.Next (Img (Img'First .. Last), Cur, Curr);
            exit when Curr.Error /= None;
            Count := Count + 1;
            exit when Cur.At_End;
         end loop;
      end;
      Assert (Count = 4, "four blocks walked");
   end Test_Write_Read;

   procedure Test_Payload_Echo (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf   : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last  : Natural := Buf'First - 1;
      Error : Error_Kind;
      Data  : Byte_Buffer (1 .. 14) :=
        [16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#,
         16#08#, 16#00#];
      Cur   : Reader.Cursor;
      Curr  : Reader.Current_Block;
      Found : Boolean := False;
   begin
      Writer.Append_SHB (Buf (1 .. Buf'Last), Last, Error);
      Writer.Append_IDB (Buf (1 .. Buf'Last), Last, Error => Error);
      Writer.Append_EPB
        (Buf (1 .. Buf'Last), Last, 0, 1_700_000_000_000_000, Data, Error);

      Cur := Reader.First (Buf'First);
      for I in 1 .. 6 loop
         Reader.Next (Buf (Buf'First .. Last), Cur, Curr);
         exit when Curr.Error /= None;
         if Curr.Kind = Kind_EPB then
            declare
               View : Packet.EPB_View;
               Nx   : Natural;
               Er   : Error_Kind;
            begin
               Packet.Parse_EPB
                 (Buf (Buf'First .. Last), Curr.Next - Curr.Total_Length,
                  Cur.Order, View, Nx, Er);
               if Er = None
                 and then View.Cap_Len = Data'Length
                 and then View.Data_Last - View.Data_First + 1 = Data'Length
               then
                  Found := True;
               end if;
            end;
            exit;
         end if;
         exit when Cur.At_End;
      end loop;
      Assert (Found, "epb payload echo");
   end Test_Payload_Echo;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      use AUnit.Test_Suites;
      S : constant Access_Test_Suite := New_Suite;
   begin
      S.Add_Test (new Test);
      return S;
   end Suite;

end Pcapng_Tests.Reader_Suite;
