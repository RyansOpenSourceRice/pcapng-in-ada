--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Fuzz/differential harness: reads one capture file, walks every block
--  through every typed view and the option iterator. All library calls
--  report Error_Kind, never raise; any unhandled exception (nonzero exit)
--  is a fuzzer crash. Usage: fuzz_harness <file> | fuzz_harness @@

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Streams.Stream_IO;
with Ada.Streams; use Ada.Streams;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.OS_Lib;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Blocks;
with Pcapng_In_Ada.SHB;
with Pcapng_In_Ada.IDB;
with Pcapng_In_Ada.Packet;
with Pcapng_In_Ada.NRB;
with Pcapng_In_Ada.ISB;
with Pcapng_In_Ada.Options;
with Pcapng_In_Ada.Reader;

procedure Fuzz_Harness is
   Max_File : constant := 16#1000000#;  --  same cap as Max_Block_Size
   type Big_Buffer is access Byte_Buffer;
   Buf_Ptr : Big_Buffer := new Byte_Buffer (1 .. Max_File);
   Buf : Byte_Buffer renames Buf_Ptr.all;
   Got : Natural := 0;
   Blocks : Natural := 0;
   Errors : Natural := 0;
begin
   if Argument_Count < 1 then
      Put_Line ("usage: fuzz_harness <file.pcapng>");
      GNAT.OS_Lib.OS_Exit (2);
   end if;
   declare
      F : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Open
        (F, Ada.Streams.Stream_IO.In_File, Argument (1));
      while (not Ada.Streams.Stream_IO.End_Of_File (F))
        and then Got < Buf'Last
      loop
         declare
            Item : Stream_Element_Array (1 .. 8_192);
            Last_E : Stream_Element_Offset;
         begin
            Ada.Streams.Stream_IO.Read (F, Item, Last_E);
            exit when Last_E < 1;
            for I in 1 .. Natural (Last_E) loop
               exit when Got >= Buf'Last;
               Got := Got + 1;
               Buf (Got) := Unsigned_8 (Item (Stream_Element_Offset (I)));
            end loop;
         end;
      end loop;
      Ada.Streams.Stream_IO.Close (F);
   exception
      when others =>
         Put_Line ("input unreadable (exit 0, not a parse bug)");
         return;
   end;

   if Got < Min_Block_Size then
      return;  --  too small: nothing to do, not a failure
   end if;

   declare
      Img : Byte_Buffer renames Buf;
      Cur : Reader.Cursor := Reader.First (Img'First);
      Curr : Reader.Current_Block;
   begin
      for I in 1 .. 2_000_000 loop
         Reader.Next (Img (Img'First .. Got), Cur, Curr);
         exit when Curr.Error /= None;
         Blocks := Blocks + 1;
         declare
            Start : constant Natural :=
              Curr.Next - Curr.Total_Length;
            Nx  : Natural;
            Er  : Error_Kind;
            Sh  : SHB.SHB_View;
            Iv  : IDB.IDB_View;
            Ev  : Packet.EPB_View;
            Sv  : Packet.SPB_View;
            Nv  : NRB.NRB_View;
            Isv : ISB.ISB_View;
         begin
            case Curr.Kind is
               when Kind_SHB =>
                  SHB.Parse_SHB
                    (Img (Img'First .. Got), Start, Sh, Nx, Er);
                  if Er = None and then Sh.Valid
                    and then Sh.Body_Last >= Sh.Body_First
                  then
                     --  Stress the option walker on every SHB.
                     declare
                        O : Options.Option_View;
                        Nxt : Natural;
                        E2 : Error_Kind;
                        P : Natural := Sh.Body_First;
                     begin
                        for J in 1 .. 1_000 loop
                           exit when P > Sh.Body_Last;
                           Options.Next_Option
                             (Img (Img'First .. Got), P,
                              Sh.Body_First, Sh.Body_Last,
                              Sh.Order, O, Nxt, E2);
                           exit when E2 /= None or else not O.Valid;
                           exit when Nxt <= P;
                           P := Nxt;
                        end loop;
                     end;
                  end if;
               when Kind_IDB =>
                  IDB.Parse_IDB
                    (Img (Img'First .. Got), Start, Cur.Order,
                     Iv, Nx, Er);
               when Kind_EPB =>
                  Packet.Parse_EPB
                    (Img (Img'First .. Got), Start, Cur.Order,
                     Ev, Nx, Er);
                  if Er = None and then Ev.Valid
                    and then Ev.Opt_First > 0
                    and then Ev.Opt_First <= Got
                  then
                     declare
                        Fst, Lst : Natural;
                        Found : Boolean;
                     begin
                        Packet.Get_EPB_Option
                          (Img (Img'First .. Got), Ev, Cur.Order,
                           Options.Comment_Opt, Fst, Lst, Found);
                        Packet.Get_EPB_Option
                          (Img (Img'First .. Got), Ev, Cur.Order,
                           Packet.EPB_Dropcount_Opt, Fst, Lst, Found);
                     end;
                  end if;
               when Kind_SPB =>
                  Packet.Parse_SPB
                    (Img (Img'First .. Got), Start, Cur.Order,
                     Sv, Nx, Er);
               when Kind_NRB =>
                  NRB.Parse_NRB
                    (Img (Img'First .. Got), Start, Cur.Order,
                     Nv, Nx, Er);
               when Kind_ISB =>
                  ISB.Parse_ISB
                    (Img (Img'First .. Got), Start, Cur.Order,
                     Isv, Nx, Er);
               when Kind_Custom | Kind_Unknown =>
                  null;
            end case;
            if Er /= None then
               Errors := Errors + 1;
            end if;
         end;
         exit when Cur.At_End;
         exit when I = 2_000_000;
      end loop;
      if Curr.Error /= None then
         Errors := Errors + 1;  --  trailing error is data, not a crash
      end if;
   end;

   Put_Line ("blocks:" & Blocks'Image & " notes:" & Errors'Image);
end Fuzz_Harness;
