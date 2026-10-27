--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;

package body Pcapng_In_Ada.Writer is

   procedure Append_SHB
     (Buf   : in out Byte_Buffer;
      Last  : in out Natural;
      Error : out Error_Kind)
   is
      Pos : Buffer_Index;
      Nx   : Natural;
      Err  : Error_Kind;
   begin
      Error := No_Space;
      if Last >= Buf'Last then
         if Last /= Buf'First - 1 or else Buf'Length < SHB_Min_Size then
            --  Allow Last = Buf'First - 1 as "empty" only when checked
            --  below; fast reject when truly full.
            null;
         end if;
      end if;

      if Last + 1 < Buf'First or else Last > Buf'Last then
         if not (Last = Buf'First - 1) then
            return;
         end if;
      end if;
      if Last = Buf'Last then
         return;
      end if;

      Pos := (if Last < Buf'First then Buf'First else Last + 1);
      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < SHB_Min_Size then
         Error := No_Space;
         return;
      end if;

      Encode_Envelope (Buf, Pos, SHB_Type, SHB_Min_Size - 12,
                       Little_Endian, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      --  Body: magic, version 1.0, section length -1, no options.
      Encode_U32_LE (Buf, Pos + 8, Byte_Order_Magic);
      Encode_U16_LE (Buf, Pos + 12, 1);
      Encode_U16_LE (Buf, Pos + 14, 0);
      Encode_U64_LE (Buf, Pos + 16, 16#FFFF_FFFF_FFFF_FFFF#);

      Last := Nx - 1;
      Error := None;
   end Append_SHB;

   procedure Append_IDB
     (Buf       : in out Byte_Buffer;
      Last      : in out Natural;
      Link_Type : Unsigned_16 := Ethernet_Link;
      Snap_Len  : Unsigned_32 := Default_Snap_Len;
      Error     : out Error_Kind)
   is
      Pos : Buffer_Index;
      Nx  : Natural;
      Err : Error_Kind;
   begin
      Error := No_Space;
      if Last + 1 < Buf'First or else Last > Buf'Last then
         if not (Last = Buf'First - 1) then
            return;
         end if;
      end if;
      if Last = Buf'Last then
         return;
      end if;
      Pos := (if Last < Buf'First then Buf'First else Last + 1);
      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < IDB_Min_Size then
         return;
      end if;

      Encode_Envelope (Buf, Pos, IDB_Type, IDB_Min_Size - 12,
                       Little_Endian, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Encode_U16_LE (Buf, Pos + 8, Link_Type);
      Encode_U16_LE (Buf, Pos + 10, 0);
      Encode_U32_LE (Buf, Pos + 12, Snap_Len);

      Last := Nx - 1;
      Error := None;
   end Append_IDB;

   procedure Append_EPB
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      If_Index : Unsigned_32;
      Ts       : Unsigned_64;
      Data     : Byte_Buffer;
      Error    : out Error_Kind)
   is
      Pos : Buffer_Index;
      Cap      : constant Natural := Data'Length;
      Pad      : constant Natural := Padding_For (Cap);
      Body_Len : Natural;
      Total    : Natural;
      Nx       : Natural;
      Err      : Error_Kind;
   begin
      Error := No_Space;
      if Cap > Max_Block_Size / 2 then
         Error := Bad_Length;
         return;
      end if;
      Body_Len := 20 + Cap + Pad;
      Total := Body_Len + 12;
      if Total > Max_Block_Size then
         Error := Bad_Length;
         return;
      end if;

      if Last + 1 < Buf'First or else Last > Buf'Last then
         if not (Last = Buf'First - 1) then
            return;
         end if;
      end if;
      if Last = Buf'Last then
         return;
      end if;
      Pos := (if Last < Buf'First then Buf'First else Last + 1);
      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < Total then
         Error := No_Space;
         return;
      end if;
      if Data'Length > 0 and then Data'First < 1 then
         Error := Bad_Length;
         return;
      end if;

      Encode_Envelope (Buf, Pos, EPB_Type, Body_Len, Little_Endian, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;

      Encode_U32_LE (Buf, Pos + 8, If_Index);
      Encode_U64_LE (Buf, Pos + 12, Ts);
      Encode_U32_LE (Buf, Pos + 20, Unsigned_32 (Cap));
      Encode_U32_LE (Buf, Pos + 24, Unsigned_32 (Cap));

      if Cap > 0 then
         if Pos + 28 + Cap - 1 > Buf'Last then
            Error := No_Space;
            return;
         end if;
         for I in 0 .. Cap - 1 loop
            pragma Loop_Invariant (Pos + 28 + I <= Buf'Last);
            Buf (Pos + 28 + I) := Data (Data'First + I);
         end loop;
         for P in 0 .. Pad - 1 loop
            pragma Loop_Invariant (True);
            exit when Pad = 0;
            if Pos + 28 + Cap + P > Buf'Last then
               Error := No_Space;
               return;
            end if;
            Buf (Pos + 28 + Cap + P) := 0;
            exit when P + 1 >= Pad;
         end loop;
      end if;

      Last := Nx - 1;
      Error := None;
   end Append_EPB;

   procedure Enc16
     (Buf : in out Byte_Buffer; Pos : Buffer_Index;
      Order : Byte_Order; Value : Unsigned_16)
   with Pre => Pos >= Buf'First and then Pos + 1 <= Buf'Last
   is
   begin
      case Order is
         when Little_Endian => Encode_U16_LE (Buf, Pos, Value);
         when Big_Endian    => Encode_U16_BE (Buf, Pos, Value);
      end case;
   end Enc16;

   procedure Enc32
     (Buf : in out Byte_Buffer; Pos : Buffer_Index;
      Order : Byte_Order; Value : Unsigned_32)
   with Pre => Pos >= Buf'First and then Pos + 3 <= Buf'Last
   is
   begin
      case Order is
         when Little_Endian => Encode_U32_LE (Buf, Pos, Value);
         when Big_Endian    => Encode_U32_BE (Buf, Pos, Value);
      end case;
   end Enc32;

   procedure Enc64
     (Buf : in out Byte_Buffer; Pos : Buffer_Index;
      Order : Byte_Order; Value : Unsigned_64)
   with Pre => Pos >= Buf'First and then Pos + 7 <= Buf'Last
   is
   begin
      case Order is
         when Little_Endian => Encode_U64_LE (Buf, Pos, Value);
         when Big_Endian    => Encode_U64_BE (Buf, Pos, Value);
      end case;
   end Enc64;

   function Start_Pos (Buf : Byte_Buffer; Last : Natural;
                       Need : Positive) return Natural
   is
   begin
      if Last + 1 < Buf'First or else Last > Buf'Last then
         if Last /= Buf'First - 1 then
            return 0;
         end if;
      end if;
      if Last = Buf'Last then
         return 0;
      end if;
      if Buf'Last - (if Last < Buf'First then Buf'First - 1 else Last)
        < Need
      then
         return 0;
      end if;
      return (if Last < Buf'First then Buf'First else Last + 1);
   end Start_Pos;

   --  Write one option TLV + zero padding at Pos. Next is one past
   --  the padded option. Caller guarantees the envelope is already
   --  reserved; this only fills bytes and never moves Last.
   procedure Write_Opt
     (Buf   : in out Byte_Buffer;
      Pos   : Buffer_Index;
      Order : Byte_Order;
      Code  : Unsigned_16;
      Value : Byte_Buffer;
      Next  : out Natural;
      Error : out Error_Kind)
   is
      Vlen : constant Natural := Value'Length;
      Pad  : constant Natural := Padding_For (Vlen);
      Total : Natural;
   begin
      Next := Pos;
      Error := No_Space;
      if Vlen > Max_Comment_Len + Max_Name_Len then
         Error := Bad_Length;
         return;
      end if;
      Total := 4 + Vlen + Pad;
      if Total > Max_Block_Size then
         Error := Bad_Length;
         return;
      end if;
      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < Total then
         return;
      end if;
      if Pos > Buf'Last - 3 then
         return;
      end if;
      Enc16 (Buf, Pos, Order, Code);
      Enc16 (Buf, Pos + 2, Order, Unsigned_16 (Vlen));
      for I in 0 .. Vlen - 1 loop
         pragma Loop_Invariant (Pos + 4 + I <= Buf'Last);
         exit when Vlen = 0;
         if Pos + 4 + I > Buf'Last then
            Error := No_Space;
            return;
         end if;
         Buf (Pos + 4 + I) := Value (Value'First + I);
         exit when I + 1 >= Vlen;
      end loop;
      for P in 0 .. Pad - 1 loop
         pragma Loop_Invariant (True);
         exit when Pad = 0;
         if Pos + 4 + Vlen + P > Buf'Last then
            Error := No_Space;
            return;
         end if;
         Buf (Pos + 4 + Vlen + P) := 0;
         exit when P + 1 >= Pad;
      end loop;
      Next := Pos + Total;
      Error := None;
   end Write_Opt;

   procedure Write_Endofopt
     (Buf   : in out Byte_Buffer;
      Pos   : Buffer_Index;
      Order : Byte_Order;
      Next  : out Natural;
      Error : out Error_Kind)
   is
      Empty : Byte_Buffer (1 .. 1) := [others => 0];
      Dummy : Byte_Buffer (1 .. 0) := [others => 0];
      pragma Unreferenced (Empty, Dummy);
   begin
      Next := Pos;
      Error := No_Space;
      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < 4 then
         return;
      end if;
      if Pos > Buf'Last - 3 then
         return;
      end if;
      Enc16 (Buf, Pos, Order, 0);
      Enc16 (Buf, Pos + 2, Order, 0);
      Next := Pos + 4;
      Error := None;
   end Write_Endofopt;

   procedure Append_SHB_Ex
     (Buf          : in out Byte_Buffer;
      Last         : in out Natural;
      Order        : Byte_Order;
      Section_Len  : Integer_64 := -1;
      Error        : out Error_Kind)
   is
      Pos : Natural;
      Nx  : Natural;
      Err : Error_Kind;
      Sec : Unsigned_64;
   begin
      Error := No_Space;
      Pos := Start_Pos (Buf, Last, SHB_Min_Size);
      if Pos = 0 or else Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      Encode_Envelope (Buf, Pos, SHB_Type, SHB_Min_Size - 12,
                       Order, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Enc32 (Buf, Pos + 8, Order, Byte_Order_Magic);
      Enc16 (Buf, Pos + 12, Order, 1);
      Enc16 (Buf, Pos + 14, Order, 0);
      Sec := (if Section_Len < 0 then 16#FFFF_FFFF_FFFF_FFFF#
              else Unsigned_64 (Section_Len));
      Enc64 (Buf, Pos + 16, Order, Sec);
      Last := Nx - 1;
      Error := None;
   end Append_SHB_Ex;

   procedure Append_IDB_Ex
     (Buf       : in out Byte_Buffer;
      Last      : in out Natural;
      Order     : Byte_Order;
      Link_Type : Unsigned_16 := Ethernet_Link;
      Snap_Len  : Unsigned_32 := Default_Snap_Len;
      Error     : out Error_Kind)
   is
      Pos : Natural;
      Nx  : Natural;
      Err : Error_Kind;
   begin
      Error := No_Space;
      Pos := Start_Pos (Buf, Last, IDB_Min_Size);
      if Pos = 0 or else Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      Encode_Envelope (Buf, Pos, IDB_Type, IDB_Min_Size - 12,
                       Order, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Enc16 (Buf, Pos + 8, Order, Link_Type);
      Enc16 (Buf, Pos + 10, Order, 0);
      Enc32 (Buf, Pos + 12, Order, Snap_Len);
      Last := Nx - 1;
      Error := None;
   end Append_IDB_Ex;

   procedure Append_EPB_Ex
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      Order    : Byte_Order;
      If_Index : Unsigned_32;
      Ts       : Unsigned_64;
      Data     : Byte_Buffer;
      Error    : out Error_Kind)
   is
      Pos  : Natural;
      Cap  : constant Natural := Data'Length;
      Pad  : constant Natural := Padding_For (Cap);
      Body_Len : Natural;
      Total : Natural;
      Nx   : Natural;
      Err  : Error_Kind;
   begin
      Error := No_Space;
      if Cap > Max_Block_Size / 2 then
         Error := Bad_Length;
         return;
      end if;
      Body_Len := 20 + Cap + Pad;
      Total := Body_Len + 12;
      if Total > Max_Block_Size then
         Error := Bad_Length;
         return;
      end if;
      Pos := Start_Pos (Buf, Last, Total);
      if Pos = 0 or else Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Data'Length > 0 and then Data'First < 1 then
         Error := Bad_Length;
         return;
      end if;
      Encode_Envelope (Buf, Pos, EPB_Type, Body_Len, Order, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Enc32 (Buf, Pos + 8, Order, If_Index);
      Enc64 (Buf, Pos + 12, Order, Ts);
      Enc32 (Buf, Pos + 20, Order, Unsigned_32 (Cap));
      Enc32 (Buf, Pos + 24, Order, Unsigned_32 (Cap));
      if Cap > 0 then
         if Pos + 28 + Cap - 1 > Buf'Last then
            Error := No_Space;
            return;
         end if;
         for I in 0 .. Cap - 1 loop
            pragma Loop_Invariant (Pos + 28 + I <= Buf'Last);
            Buf (Pos + 28 + I) := Data (Data'First + I);
         end loop;
         for P in 0 .. Pad - 1 loop
            pragma Loop_Invariant (True);
            exit when Pad = 0;
            if Pos + 28 + Cap + P > Buf'Last then
               Error := No_Space;
               return;
            end if;
            Buf (Pos + 28 + Cap + P) := 0;
            exit when P + 1 >= Pad;
         end loop;
      end if;
      Last := Nx - 1;
      Error := None;
   end Append_EPB_Ex;

   procedure Append_SPB_Ex
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      Order    : Byte_Order;
      Orig_Len : Unsigned_32;
      Data     : Byte_Buffer;
      Error    : out Error_Kind)
   is
      Pos   : Natural;
      Cap   : constant Natural := Data'Length;
      Pad   : constant Natural := Padding_For (Cap);
      Frame : Natural;
      Body_Len  : Natural;
      Total : Natural;
      Nx    : Natural;
      Err   : Error_Kind;
   begin
      Error := No_Space;
      if Cap > Max_Block_Size / 2 then
         Error := Bad_Length;
         return;
      end if;
      --  SPB body after orig_len must stay 32-bit aligned: pad data.
      Frame := Cap + Pad;
      if Frame mod 4 /= 0 then
         Error := Bad_Length;
         return;
      end if;
      Body_Len := 4 + Frame;
      Total := Body_Len + 12;
      if Total > Max_Block_Size or else Total < SPB_Min_Size then
         Error := Bad_Length;
         return;
      end if;
      Pos := Start_Pos (Buf, Last, Total);
      if Pos = 0 or else Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Data'Length > 0 and then Data'First < 1 then
         Error := Bad_Length;
         return;
      end if;
      Encode_Envelope (Buf, Pos, SPB_Type, Body_Len, Order, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Enc32 (Buf, Pos + 8, Order, Orig_Len);
      for I in 0 .. Cap - 1 loop
         pragma Loop_Invariant (Pos + 12 + I <= Buf'Last);
         exit when Cap = 0;
         if Pos + 12 + I > Buf'Last then
            Error := No_Space;
            return;
         end if;
         Buf (Pos + 12 + I) := Data (Data'First + I);
         exit when I + 1 >= Cap;
      end loop;
      for P in 0 .. Pad - 1 loop
         pragma Loop_Invariant (True);
         exit when Pad = 0;
         if Pos + 12 + Cap + P > Buf'Last then
            Error := No_Space;
            return;
         end if;
         Buf (Pos + 12 + Cap + P) := 0;
         exit when P + 1 >= Pad;
      end loop;
      Last := Nx - 1;
      Error := None;
   end Append_SPB_Ex;

   procedure Append_SHB_With_Comment
     (Buf     : in out Byte_Buffer;
      Last    : in out Natural;
      Order   : Byte_Order;
      Comment : Byte_Buffer;
      Error   : out Error_Kind)
   is
      Pos   : Natural;
      Vlen  : constant Natural := Comment'Length;
      Pad   : constant Natural := Padding_For (Vlen);
      Opt   : Natural;
      Body_Len  : Natural;
      Total : Natural;
      Nx    : Natural;
      Err   : Error_Kind;
      O_Nx  : Natural;
      E_Nx  : Natural;
   begin
      Error := No_Space;
      if Vlen = 0 or else Vlen > Max_Comment_Len then
         Error := Bad_Length;
         return;
      end if;
      if Comment'First < 1 then
         Error := Bad_Length;
         return;
      end if;
      Opt := 4 + Vlen + Pad + 4;
      Body_Len := 16 + Opt;
      Total := Body_Len + 12;
      if Total > Max_Block_Size then
         Error := Bad_Length;
         return;
      end if;
      Pos := Start_Pos (Buf, Last, Total);
      if Pos = 0 or else Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      Encode_Envelope (Buf, Pos, SHB_Type, Body_Len, Order, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Enc32 (Buf, Pos + 8, Order, Byte_Order_Magic);
      Enc16 (Buf, Pos + 12, Order, 1);
      Enc16 (Buf, Pos + 14, Order, 0);
      Enc64 (Buf, Pos + 16, Order, 16#FFFF_FFFF_FFFF_FFFF#);
      Write_Opt (Buf, Pos + 24, Order, 1, Comment, O_Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Write_Endofopt (Buf, O_Nx, Order, E_Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      if E_Nx /= Pos + Total - 4 then
         Error := Bad_Length;
         return;
      end if;
      Last := Nx - 1;
      Error := None;
   end Append_SHB_With_Comment;

   procedure Append_IDB_With_Name
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      Order    : Byte_Order;
      Link     : Unsigned_16 := Ethernet_Link;
      Snap     : Unsigned_32 := Default_Snap_Len;
      If_Name  : Byte_Buffer;
      Error    : out Error_Kind)
   is
      Pos   : Natural;
      Vlen  : constant Natural := If_Name'Length;
      Pad   : constant Natural := Padding_For (Vlen);
      Opt   : Natural;
      Body_Len  : Natural;
      Total : Natural;
      Nx    : Natural;
      Err   : Error_Kind;
      O_Nx  : Natural;
      E_Nx  : Natural;
   begin
      Error := No_Space;
      if Vlen = 0 or else Vlen > Max_Name_Len then
         Error := Bad_Length;
         return;
      end if;
      if If_Name'First < 1 then
         Error := Bad_Length;
         return;
      end if;
      Opt := 4 + Vlen + Pad + 4;
      Body_Len := 8 + Opt;
      Total := Body_Len + 12;
      if Total > Max_Block_Size then
         Error := Bad_Length;
         return;
      end if;
      Pos := Start_Pos (Buf, Last, Total);
      if Pos = 0 or else Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      Encode_Envelope (Buf, Pos, IDB_Type, Body_Len, Order, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Enc16 (Buf, Pos + 8, Order, Link);
      Enc16 (Buf, Pos + 10, Order, 0);
      Enc32 (Buf, Pos + 12, Order, Snap);
      Write_Opt (Buf, Pos + 16, Order, 2, If_Name, O_Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Write_Endofopt (Buf, O_Nx, Order, E_Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      if E_Nx /= Pos + Total - 4 then
         Error := Bad_Length;
         return;
      end if;
      Last := Nx - 1;
      Error := None;
   end Append_IDB_With_Name;

   procedure Append_EPB_With_Comment
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      Order    : Byte_Order;
      If_Index : Unsigned_32;
      Ts       : Unsigned_64;
      Data     : Byte_Buffer;
      Comment  : Byte_Buffer;
      Error    : out Error_Kind)
   is
      Pos    : Natural;
      Cap    : constant Natural := Data'Length;
      Pad    : constant Natural := Padding_For (Cap);
      Vlen   : constant Natural := Comment'Length;
      C_Pad  : constant Natural := Padding_For (Vlen);
      O_Size : Natural;
      Body_Len   : Natural;
      Total  : Natural;
      Nx     : Natural;
      Err    : Error_Kind;
      O_Pos  : Natural;
      O_Nx   : Natural;
      E_Nx   : Natural;
   begin
      Error := No_Space;
      if Cap > Max_Block_Size / 2 then
         Error := Bad_Length;
         return;
      end if;
      if Vlen = 0 or else Vlen > Max_Comment_Len then
         Error := Bad_Length;
         return;
      end if;
      if Comment'First < 1 then
         Error := Bad_Length;
         return;
      end if;
      if Data'Length > 0 and then Data'First < 1 then
         Error := Bad_Length;
         return;
      end if;
      O_Size := 4 + Vlen + C_Pad + 4;
      Body_Len := 20 + Cap + Pad + O_Size;
      Total := Body_Len + 12;
      if Total > Max_Block_Size or else Total < EPB_Min_Size then
         Error := Bad_Length;
         return;
      end if;
      Pos := Start_Pos (Buf, Last, Total);
      if Pos = 0 or else Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      Encode_Envelope (Buf, Pos, EPB_Type, Body_Len, Order, Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Enc32 (Buf, Pos + 8, Order, If_Index);
      Enc64 (Buf, Pos + 12, Order, Ts);
      Enc32 (Buf, Pos + 20, Order, Unsigned_32 (Cap));
      Enc32 (Buf, Pos + 24, Order, Unsigned_32 (Cap));
      for I in 0 .. Cap - 1 loop
         pragma Loop_Invariant (Pos + 28 + I <= Buf'Last);
         exit when Cap = 0;
         if Pos + 28 + I > Buf'Last then
            Error := No_Space;
            return;
         end if;
         Buf (Pos + 28 + I) := Data (Data'First + I);
         exit when I + 1 >= Cap;
      end loop;
      for P in 0 .. Pad - 1 loop
         pragma Loop_Invariant (True);
         exit when Pad = 0;
         if Pos + 28 + Cap + P > Buf'Last then
            Error := No_Space;
            return;
         end if;
         Buf (Pos + 28 + Cap + P) := 0;
         exit when P + 1 >= Pad;
      end loop;
      O_Pos := Pos + 28 + Cap + Pad;
      Write_Opt (Buf, O_Pos, Order, 1, Comment, O_Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      Write_Endofopt (Buf, O_Nx, Order, E_Nx, Err);
      if Err /= None then
         Error := Err;
         return;
      end if;
      if E_Nx /= Pos + Total - 4 then
         Error := Bad_Length;
         return;
      end if;
      Last := Nx - 1;
      Error := None;
   end Append_EPB_With_Comment;

end Pcapng_In_Ada.Writer;
