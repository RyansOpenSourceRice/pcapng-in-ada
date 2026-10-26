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
with Pcapng_In_Ada.SHB;
with Pcapng_In_Ada.IDB;
with Pcapng_In_Ada.Packet;
with Pcapng_In_Ada.NRB;
with Pcapng_In_Ada.ISB;
with Pcapng_In_Ada.Options;
with Pcapng_In_Ada.Stream;
with Pcapng_In_Ada.Diag;

package body Pcapng_Tests.V02_Suite is

   type Test is new Test_Cases.Test_Case with null record;

   overriding function Name (T : Test) return Message_String;
   overriding procedure Register_Tests (T : in out Test);

   procedure T_BE (T : in out Test_Cases.Test_Case'Class);
   procedure T_Options (T : in out Test_Cases.Test_Case'Class);
   procedure T_SPB (T : in out Test_Cases.Test_Case'Class);
   procedure T_NRB_ISB (T : in out Test_Cases.Test_Case'Class);
   procedure T_Stream (T : in out Test_Cases.Test_Case'Class);
   procedure T_Section_Flip (T : in out Test_Cases.Test_Case'Class);
   procedure T_Diag (T : in out Test_Cases.Test_Case'Class);

   overriding function Name (T : Test) return Message_String is
   begin
      pragma Unreferenced (T);
      return Format ("V02");
   end Name;

   overriding procedure Register_Tests (T : in out Test) is
   begin
      Registration.Register_Routine (T, T_BE'Access, "be roundtrip");
      Registration.Register_Routine (T, T_Options'Access, "options roundtrip");
      Registration.Register_Routine (T, T_SPB'Access, "spb be");
      Registration.Register_Routine (T, T_NRB_ISB'Access, "nrb/isb views");
      Registration.Register_Routine (T, T_Stream'Access, "stream chunking");
      Registration.Register_Routine
        (T, T_Section_Flip'Access, "le->be section flip walks 6");
      Registration.Register_Routine (T, T_Diag'Access, "diag tracker");
   end Register_Tests;

   function Eq_Bytes (Buf : Byte_Buffer; F, L : Natural;
                      Ref : Byte_Buffer) return Boolean
   is
   begin
      if L + 1 - F /= Ref'Length then
         return False;
      end if;
      for I in 0 .. Ref'Length - 1 loop
         if Buf (F + I) /= Ref (Ref'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Eq_Bytes;

   procedure T_BE (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err : Error_Kind;
      Data : Byte_Buffer (1 .. 4) := [1, 2, 3, 4];
      Cur : Reader.Cursor := Reader.First (Buf'First);
      Curr : Reader.Current_Block;
      N : Natural := 0;
   begin
      Writer.Append_SHB_Ex (Buf, Last, Big_Endian, Error => Err);
      Assert (Err = None, "be shb");
      Writer.Append_IDB_Ex (Buf, Last, Big_Endian, Error => Err);
      Assert (Err = None, "be idb");
      Writer.Append_EPB_Ex (Buf, Last, Big_Endian, 0,
                            12_345, Data, Err);
      Assert (Err = None, "be epb");
      Cur := Reader.First (Buf'First);
      for I in 1 .. 6 loop
         Reader.Next (Buf (Buf'First .. Last), Cur, Curr);
         exit when Curr.Error /= None;
         N := N + 1;
         exit when Cur.At_End;
      end loop;
      Assert (N = 3, "be 3 blocks");
      Assert (Cur.Order = Big_Endian, "be order tracked");
   end T_BE;

   procedure T_Options (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err : Error_Kind;
      Cmt : Byte_Buffer (1 .. 5) := [72, 69, 76, 76, 79];
      Nm  : Byte_Buffer (1 .. 4) := [101, 116, 104, 48];
      Data : Byte_Buffer (1 .. 2) := [16#AA#, 16#BB#];
      Sh : SHB.SHB_View;
      Iv : IDB.IDB_View;
      Ev : Packet.EPB_View;
      Nx : Natural;
      F, L : Natural;
      Found : Boolean;
      P : Natural;
   begin
      Writer.Append_SHB_With_Comment (Buf, Last, Little_Endian, Cmt, Err);
      Assert (Err = None, "shb+cmt write");
      P := Buf'First;
      SHB.Parse_SHB (Buf (Buf'First .. Last), P, Sh, Nx, Err);
      Assert (Err = None and Sh.Valid, "shb+cmt parse");
      SHB.Get_Option (Buf (Buf'First .. Last), Sh, Little_Endian,
                      Options.Comment_Opt, F, L, Found);
      Assert (Found and Eq_Bytes (Buf, F, L, Cmt), "shb comment found");

      Writer.Append_IDB_With_Name (Buf, Last, Little_Endian,
                                   Writer.Ethernet_Link,
                                   Writer.Default_Snap_Len, Nm, Err);
      Assert (Err = None, "idb+name write");
      IDB.Parse_IDB (Buf (Buf'First .. Last), Nx, Little_Endian,
                     Iv, Nx, Err);
      Assert (Err = None and Iv.Valid, "idb+name parse");
      IDB.Get_Option (Buf (Buf'First .. Last), Iv, Little_Endian,
                      IDB.If_Name_Opt, F, L, Found);
      Assert (Found and Eq_Bytes (Buf, F, L, Nm), "idb name found");

      Writer.Append_EPB_With_Comment (Buf, Last, Little_Endian, 0,
                                      99, Data, Cmt, Err);
      Assert (Err = None, "epb+cmt write");
      Packet.Parse_EPB (Buf (Buf'First .. Last), Nx, Little_Endian,
                        Ev, Nx, Err);
      Assert (Err = None and Ev.Valid, "epb+cmt parse");
      Packet.Get_EPB_Option (Buf (Buf'First .. Last), Ev, Little_Endian,
                             Options.Comment_Opt, F, L, Found);
      Assert (Found and Eq_Bytes (Buf, F, L, Cmt), "epb comment found");
   end T_Options;

   procedure T_SPB (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf : Byte_Buffer (1 .. 1_024) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err : Error_Kind;
      Data : Byte_Buffer (1 .. 8) := [others => 7];
      Sv : Packet.SPB_View;
      Nx : Natural;
      Sh : SHB.SHB_View;
      Sn : Natural;
   begin
      Writer.Append_SHB_Ex (Buf, Last, Big_Endian, Error => Err);
      SHB.Parse_SHB (Buf (Buf'First .. 64), Buf'First, Sh, Sn, Err);
      Assert (Err = None, "spb needs shb");
      Writer.Append_SPB_Ex (Buf, Last, Big_Endian, 8, Data, Err);
      Assert (Err = None, "spb be write");
      Packet.Parse_SPB (Buf (Buf'First .. Last), Sn, Big_Endian,
                        Sv, Nx, Err);
      Assert (Err = None and Sv.Valid and Sv.Orig_Len = 8, "spb be parse");
   end T_SPB;

   procedure T_NRB_ISB (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf : Byte_Buffer (1 .. 128) := [others => 0];
      Nv : NRB.NRB_View;
      Sv : ISB.ISB_View;
      Nx : Natural;
      Err : Error_Kind;
      LE : constant Byte_Order := Little_Endian;
   begin
      Buf (1) := 4; Buf (5) := 24;
      Buf (9) := 1; Buf (11) := 4;
      Buf (13) := 192; Buf (14) := 168; Buf (15) := 0; Buf (16) := 1;
      Buf (17) := 0; Buf (18) := 0; Buf (19) := 0; Buf (20) := 0;
      Buf (21) := 24;
      NRB.Parse_NRB (Buf (1 .. 24), 1, LE, Nv, Nx, Err);
      Assert (Err = None and Nv.Valid
              and Nv.Record_Count = 2 and Nx = 25, "nrb parse");

      Buf := [others => 0];
      Buf (1) := 5; Buf (5) := 24;
      Buf (21) := 24;
      ISB.Parse_ISB (Buf (1 .. 24), 1, LE, Sv, Nx, Err);
      Assert (Err = None and Sv.Valid and Nx = 25, "isb parse");
   end T_NRB_ISB;

   procedure T_Stream (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Buf : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err : Error_Kind;
      S : Stream.State := Stream.Init;
      C1, C2 : Natural;
      E1, E2 : Error_Kind;
      N1, N2 : Natural;
   begin
      Writer.Append_SHB (Buf, Last, Err);
      Writer.Append_IDB (Buf, Last, Error => Err);
      Stream.Consume (S, Buf (Buf'First .. Last),
                      Buf'First, 28, C1, E1, N1);
      Assert (E1 = None and N1 = 1 and C1 = 28, "stream first chunk");
      Stream.Consume (S, Buf (Buf'First .. Last),
                      Buf'First + C1, Last, C2, E2, N2);
      Assert (E2 = None and N2 = 1, "stream second chunk");
      Assert (C1 + C2 = Last, "stream consumed all");
   end T_Stream;

   procedure T_Section_Flip (T : in out Test_Cases.Test_Case'Class) is
      --  Regression: an LE section followed by a BE section must walk
      --  all 6 blocks (the BE SHB total-length is garbage in LE order).
      pragma Unreferenced (T);
      Buf  : Byte_Buffer (1 .. 8_192) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Fr   : Byte_Buffer (1 .. 4) := [1, 2, 3, 4];
      Cur  : Reader.Cursor := Reader.First (Buf'First);
      Curr : Reader.Current_Block;
      N    : Natural := 0;
      Saw_BE : Boolean := False;
   begin
      Writer.Append_SHB (Buf, Last, Err);
      Writer.Append_IDB (Buf, Last, Error => Err);
      Writer.Append_EPB (Buf, Last, 0, 1, Fr, Err);
      Writer.Append_SHB_Ex (Buf, Last, Big_Endian, Error => Err);
      Writer.Append_IDB_Ex (Buf, Last, Big_Endian, Error => Err);
      Writer.Append_EPB_Ex (Buf, Last, Big_Endian, 1, 2, Fr, Err);
      Assert (Err = None, "flip setup");
      Cur := Reader.First (Buf'First);
      for I in 1 .. 8 loop
         Reader.Next (Buf (Buf'First .. Last), Cur, Curr);
         exit when Curr.Error /= None;
         N := N + 1;
         if Cur.Order = Big_Endian then
            Saw_BE := True;
         end if;
         exit when Cur.At_End;
      end loop;
      Assert (N = 6, "flip walks 6 blocks");
      Assert (Saw_BE, "flip tracks be order");
      Assert (Curr.Error = None, "flip no error");
   end T_Section_Flip;

   procedure T_Diag (T : in out Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Tr : Diag.Tracker := Diag.Init;
      L1, L2, L3 : Diag.Location;
   begin
      Diag.Note_Block (Tr, Kind_SHB, False, 1, L1);
      Diag.Note_Block (Tr, Kind_IDB, False, 29, L2);
      Diag.Note_Block (Tr, Kind_SHB, False, 57, L3);
      Assert (L1.Byte_Offset = 1
              and L2.Byte_Offset = 29 and L3.Byte_Offset = 57,
              "diag offsets");
      Assert (L1.Section_Index = 1 and L3.Section_Index = 2,
              "diag sections");
      Assert (L1.Block_Index = 1
              and L2.Block_Index = 2 and L3.Block_Index = 3,
              "diag blocks");
   end T_Diag;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      use AUnit.Test_Suites;
      S : constant Access_Test_Suite := New_Suite;
   begin
      S.Add_Test (new Test);
      return S;
   end Suite;

end Pcapng_Tests.V02_Suite;
