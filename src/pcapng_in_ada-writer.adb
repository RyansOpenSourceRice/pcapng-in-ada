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

end Pcapng_In_Ada.Writer;
