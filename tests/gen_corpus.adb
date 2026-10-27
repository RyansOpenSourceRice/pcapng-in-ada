--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Corpus generator: emits the small deterministic capture files under
--  tests/corpus/ from the library's own writer (plus a few hand-rolled
--  blocks for NRB/ISB/unknown-option/truncation). Re-run after any
--  framing change: ./bin/gen_corpus
--
--  Deliberately NOT part of `alr test`; it writes files, it asserts nothing.

with Ada.Streams.Stream_IO;
with Ada.Streams; use Ada.Streams;
with Ada.Directories;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Writer;

procedure Gen_Corpus is
   Out_Dir : constant String := "tests/corpus/";

   procedure Write_File (Name : String; Buf : Byte_Buffer; Last : Natural) is
      F : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Create
        (F, Ada.Streams.Stream_IO.Out_File, Out_Dir & Name);
      declare
         Raw : Stream_Element_Array
           (1 .. Stream_Element_Offset (Last));
      begin
         for I in 1 .. Last loop
            Raw (Stream_Element_Offset (I)) :=
              Stream_Element (Buf (I));
         end loop;
         Stream_Element_Array'Write
           (Ada.Streams.Stream_IO.Stream (F), Raw);
      end;
      Ada.Streams.Stream_IO.Close (F);
   end Write_File;

   procedure Emit_LE_Basic is
      Buf  : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Fr   : Byte_Buffer (1 .. 14) :=
        [16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#,
         16#08#, 16#00#];
   begin
      Writer.Append_SHB (Buf, Last, Err);
      Writer.Append_IDB (Buf, Last, Error => Err);
      Writer.Append_EPB (Buf, Last, 0, 1_700_000_000_000_000, Fr, Err);
      Writer.Append_EPB (Buf, Last, 0, 1_700_000_000_000_001, Fr, Err);
      Write_File ("le_basic.pcapng", Buf, Last);
   end Emit_LE_Basic;

   procedure Emit_BE_Basic is
      Buf  : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Fr   : Byte_Buffer (1 .. 4) := [1, 2, 3, 4];
   begin
      Writer.Append_SHB_Ex (Buf, Last, Big_Endian, Error => Err);
      Writer.Append_IDB_Ex (Buf, Last, Big_Endian, Error => Err);
      Writer.Append_EPB_Ex (Buf, Last, Big_Endian, 0, 12_345, Fr, Err);
      Write_File ("be_basic.pcapng", Buf, Last);
   end Emit_BE_Basic;

   procedure Emit_With_Comment is
      Buf  : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Cmt  : Byte_Buffer (1 .. 5) := [72, 69, 76, 76, 79];
      Nm   : Byte_Buffer (1 .. 4) := [101, 116, 104, 48];
      Fr   : Byte_Buffer (1 .. 2) := [16#AA#, 16#BB#];
   begin
      Writer.Append_SHB_With_Comment (Buf, Last, Little_Endian, Cmt, Err);
      Writer.Append_IDB_With_Name (Buf, Last, Little_Endian,
                                   Writer.Ethernet_Link,
                                   Writer.Default_Snap_Len, Nm, Err);
      Writer.Append_EPB_With_Comment
        (Buf, Last, Little_Endian, 0, 99, Fr, Cmt, Err);
      Write_File ("with_comment.pcapng", Buf, Last);
   end Emit_With_Comment;

   procedure Emit_Snaplen is
      --  caplen 10 < origlen 1500: snaplen-truncated, must parse fine.
      Buf  : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Fr   : Byte_Buffer (1 .. 10) := [others => 16#AB#];
      EPB_At : Natural;
   begin
      Writer.Append_SHB (Buf, Last, Err);
      Writer.Append_IDB (Buf, Last, Error => Err);
      EPB_At := Last + 1;
      Writer.Append_EPB (Buf, Last, 0, 42, Fr, Err);
      Buf (EPB_At + 24) := 16#DC#;
      Buf (EPB_At + 25) := 16#05#;
      Write_File ("snaplen.pcapng", Buf, Last);
   end Emit_Snaplen;

   procedure Emit_NRB_ISB is
      Buf  : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Base : Natural;
   begin
      Writer.Append_SHB (Buf, Last, Err);
      Writer.Append_IDB (Buf, Last, Error => Err);
      --  NRB, total 24: type 4, one IPv4 record, end record.
      Base := Last + 1;
      Buf (Base + 0) := 4;
      Buf (Base + 4) := 24;
      Buf (Base + 8) := 1;   --  ipv4 rec
      Buf (Base + 10) := 4;  --  len 4
      Buf (Base + 12) := 192;
      Buf (Base + 13) := 168;
      Buf (Base + 14) := 0;
      Buf (Base + 15) := 1;
      --  end record already zero; trailer:
      Buf (Base + 20) := 24;
      Last := Base + 23;
      --  ISB, total 24: type 5, zeros.
      Base := Last + 1;
      Buf (Base + 0) := 5;
      Buf (Base + 4) := 24;
      Buf (Base + 20) := 24;
      Last := Base + 23;
      Write_File ("nrb_isb.pcapng", Buf, Last);
   end Emit_NRB_ISB;

   procedure Emit_Unknown_Opt is
      --  Valid EPB+comment with the option code patched to 99:
      --  parsers must skip it, comment lookup misses, walk continues.
      Buf  : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Cmt  : Byte_Buffer (1 .. 5) := [72, 69, 76, 76, 79];
      Fr   : Byte_Buffer (1 .. 2) := [16#AA#, 16#BB#];
      EPB_At : Natural;
      Opt_At : Natural;
   begin
      Writer.Append_SHB (Buf, Last, Err);
      Writer.Append_IDB (Buf, Last, Error => Err);
      EPB_At := Last + 1;
      Writer.Append_EPB_With_Comment
        (Buf, Last, Little_Endian, 0, 99, Fr, Cmt, Err);
      Opt_At := EPB_At + 28 + 2 + 2;  --  hdr + if/ts/cap/orig + data + pad
      Buf (Opt_At) := 99;
      Buf (Opt_At + 1) := 0;
      Write_File ("unknown_opt.pcapng", Buf, Last);
   end Emit_Unknown_Opt;

   procedure Emit_Multi_Section is
      Buf  : Byte_Buffer (1 .. 8_192) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Fr   : Byte_Buffer (1 .. 4) := [1, 2, 3, 4];
   begin
      Writer.Append_SHB (Buf, Last, Err);
      Writer.Append_IDB (Buf, Last, Error => Err);
      Writer.Append_EPB (Buf, Last, 0, 1, Fr, Err);
      Writer.Append_SHB_Ex (Buf, Last, Big_Endian, Error => Err);
      Writer.Append_IDB_Ex (Buf, Last, Big_Endian, Error => Err);
      Writer.Append_EPB_Ex (Buf, Last, Big_Endian, 1, 2, Fr, Err);
      Write_File ("multi_section.pcapng", Buf, Last);
   end Emit_Multi_Section;

   procedure Emit_Truncated is
      Buf  : Byte_Buffer (1 .. 4_096) := [others => 0];
      Last : Natural := Buf'First - 1;
      Err  : Error_Kind;
      Fr   : Byte_Buffer (1 .. 64) := [others => 16#CD#];
   begin
      Writer.Append_SHB (Buf, Last, Err);
      Writer.Append_IDB (Buf, Last, Error => Err);
      Writer.Append_EPB (Buf, Last, 0, 7, Fr, Err);
      Write_File ("truncated_tail.pcapng", Buf, Last - 10);
   end Emit_Truncated;

begin
   if not Ada.Directories.Exists (Out_Dir) then
      Ada.Directories.Create_Directory (Out_Dir);
   end if;
   Emit_LE_Basic;
   Emit_BE_Basic;
   Emit_With_Comment;
   Emit_Snaplen;
   Emit_NRB_ISB;
   Emit_Unknown_Opt;
   Emit_Multi_Section;
   Emit_Truncated;
end Gen_Corpus;
