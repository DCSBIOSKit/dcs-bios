BIOS.protocol.beginModule("Mosquito", 0x7000)
BIOS.protocol.setExportModuleAircrafts({"MosquitoFBMkVI"})

local documentation = moduleBeingDefined.documentation

local document = BIOS.util.document  

local parse_indication = BIOS.util.parse_indication

local defineFloat = BIOS.util.defineFloat
local defineIndicatorLight = BIOS.util.defineIndicatorLight
local definePushButton = BIOS.util.definePushButton
local definePotentiometer = BIOS.util.definePotentiometer
local defineRotary = BIOS.util.defineRotary
local define3PosTumb = BIOS.util.define3PosTumb
local defineTumb = BIOS.util.defineTumb
local defineToggleSwitch = BIOS.util.defineToggleSwitch
local defineIntegerFromGetter = BIOS.util.defineIntegerFromGetter

-- remove Arg# Pilot 500

--Main Pit
definePushButton("STICK_BTN_A", 5, 3005, 245, "Stick", "Stick Button A - MG Trigger")
definePushButton("STICK_BTN_B1", 5, 3006, 246, "Stick", "Stick Button B1 - Cannon Trigger")	
definePushButton("STICK_BTN_B2", 5, 3007, 244, "Stick", "Stick Button B2 - Secondary & Drop Ordnance Trigger")
definePotentiometer("STICK_WH_BRK", 2, 3001, 248, {0, 1}, "Stick", "Stick Wheel Brakes Lever")
definePushButton("STICK_WH_BRK_LOCK", 2, 3004, 291, "Stick", "Stick Wheel Brakes Lever Lock")
defineToggleSwitch("WINDOW_CONTROL_L", 2, 3022, 251, "Cockpit", "Left Side Window Open/Close Control")
defineToggleSwitch("WINDOW_CONTROL_R", 2, 3063, 253, "Cockpit", "Right Side Window Open/Close Control")
definePushButton("ARMOR_HEADREST", 2, 3071, 312, "Cockpit", "Armor Headrest Lock")
definePotentiometer("GUNSIGHT_RANGE", 5, 3045, 107, {0, 1}, "Reflector Sight", "Reflector Sight Setter Rings Range")
definePotentiometer("GUNSIGHT_SPAN", 5, 3048, 108, {0, 1}, "Reflector Sight", "Reflector Sight Setter Rings Span")
definePotentiometer("GUNSIGHT_DIM", 4, 3009, 13, {0, 1}, "Reflector Sight" , "Reflector Sight Dimmer")

--J.B.A.
defineToggleSwitch("MASTER_SWITCH", 3, 3009, 124, "JBA", "Master Gate Switch")
defineToggleSwitch("PORT_MAGNETO_1", 3, 3001, 125, "JBA", "Magneto Switch Port 1")
defineToggleSwitch("PORT_MAGNETO_2", 3, 3003, 126, "JBA", "Magneto Switch Port 2")
defineToggleSwitch("PORT_START_CVR", 3, 3052, 129, "JBA", "Starter Switch Cover Port")
definePushButton("PORT_START_SW", 3, 3054, 131, "JBA", "Starter Switch Port")
defineToggleSwitch("PORT_BOOST_CVR", 3, 3058, 133, "JBA", "Booster Switch Cover Port")
definePushButton("PORT_BOOST_SW", 3, 3060, 135, "JBA", "Booster Switch Port")
defineToggleSwitch("PORT_AIRSCREW", 3, 3081, 354, "JBA", "Feathering Switch Port")
defineToggleSwitch("PORT_RAD_FLAP", 4, 3062, 112, "JBA", "Radiator Flap Switch Port")
defineToggleSwitch("STBD_RAD_FLAP", 4, 3064, 113, "JBA", "Radiator Flap Switch Starboard")
defineToggleSwitch("STBD_AIRSCREW", 3, 3082, 355, "JBA", "Feathering Switch Starboard")
defineToggleSwitch("STBD_BOOST_CVR", 3, 3061, 134, "JBA", "Booster Switch Cover Starboard")
definePushButton("STBD_BOOST_SW", 3, 3063, 136, "JBA", "Booster Switch Starboard")
defineToggleSwitch("STBD_START_CVR", 3, 3055, 130, "JBA", "Starter Switch Cover Starboard")
definePushButton("STBD_START_SW", 3, 3057, 132, "JBA", "Starter Switch Starboard")
defineToggleSwitch("STBD_MAGNETO_1", 3, 3005, 127, "JBA", "Magneto Switch Starboard 1")
defineToggleSwitch("STBD_MAGNETO_2", 3, 3007, 128, "JBA", "Magneto Switch Starboard 2")
definePotentiometer("FLOOD_L_DIM_R", 4, 3053, 14, {0, 1}, "JBA", "Right Flood Light Dimmer")
definePotentiometer("BOX_B_DIM", 4, 3056, 15, {0, 1}, "JBA", "J.B.B. Flood Light Dimmer")
defineToggleSwitch("AIR_FILTER", 4, 3066, 114, "JBA", "Tropical Air Filter Switch")
defineToggleSwitch("FUEL_PUMP_L_CVR", 2, 3065, 282, "JBA", "Fuel Pump Light Cover")

defineIndicatorLight("FUEL_PUMP_L", 281, "JBA Lights", "Fuel Pump Light (yellow)")

--Main Panel
defineRotary("REP_COMP", 8, 3001, 49, "Main Panel", "Repeater Compass Course Set")
defineRotary("ALT_SET", 2, 3010, 72, "Main Panel", "Altimeter Set")
defineRotary("DI_SET", 2, 3013, 74, "Main Panel", "Directional Gyro Set")
defineRotary("UC_BLIND", 2, 3018, 304, "Main Panel", "U/C Indicator Blind Up/Down")
defineToggleSwitch("PORT_OXY_VALVE", 15, 3003, 84, "Main Panel", "Oxygen Regulator Port")
definePushButton("BOOST_CUT_OFF", 3, 3049, 292, "Main Panel", "Boost Cut-Off T-Handle")
defineToggleSwitch("PORT_LAND_L_SW", 4, 3018, 62, "Main Panel", "Landing Light Switch Port")
defineToggleSwitch("STBD_LAND_L_SW", 4, 3020, 63, "Main Panel", "Landing Light Switch Starboard")
define3PosTumb("BOMB_DOORS_LVR", 17, 3001, 115, "Main Panel", "Bomb Doors Lever")
define3PosTumb("CHASSIS_LVR", 17, 3002, 116, "Main Panel", "Chassis Lever")
define3PosTumb("FLAPS_LVR", 17, 3003, 118, "Main Panel", "Flaps Lever")
defineToggleSwitch("CHASSIS_GATE", 17, 3004, 117, "Main Panel", "Chassis Lever Gate")
defineToggleSwitch("FLAPS_GATE", 17, 3006, 119, "Main Panel", "Flaps Lever Gate")
defineToggleSwitch("GUN_MASTER_CVR", 5, 3001, 120, "Main Panel", "Gun Firing Master Switch Cover")
defineTumb("GUN_MASTER", 5, 3003, 121, 2, {-1, 1}, nil, false, "Main Panel", "Gun Firing Master Switch")
defineToggleSwitch("DE_ICE_PUMP", 23, 3001, 370, "Main Panel", "De-Ice Glycol Pump Handle")
defineRotary("RUDDER_TRIM", 2, 3053, 111, "Main Panel", "Rudder Trim")
defineRotary("AILERON_TRIM", 2, 3051, 280, "Main Panel", "Aileron Trim")
definePotentiometer("BOMB_PANEL_DIM", 4, 3059, 16, {0, 1}, "Main Panel" , "Bomb Panel Flood Dimmer")
defineToggleSwitch("BOMB_DOOR_L_CVR", 2, 3067, 284, "Main Panel", "Bomb Door Light Cover")
defineToggleSwitch("JETT_CONT_CVR", 5, 3056, 144, "Main Panel", "Container Jettison Cover")
definePushButton("JETT_CONT", 5, 3058, 145, "Main Panel", "Container Jettison Button")
defineToggleSwitch("BOMB_PANEL_CVR", 5, 3059, 311, "Main Panel", "Bomb Panel Cover")
defineToggleSwitch("CINE_CAM", 5, 3061, 143, "Main Panel", "Cine Camera Changeover Switch")
defineToggleSwitch("WING_ORD_1", 5, 3063, 148, "Main Panel", "Wing Ordnance 1 Switch")
defineToggleSwitch("WING_ORD_2", 5, 3065, 149, "Main Panel", "Wing Ordnance 2 Switch")
defineToggleSwitch("FUSELAGE_BOMB_3", 5, 3067, 150, "Main Panel", "Fuselage Bombs 3 Switch")
defineToggleSwitch("FUSELAGE_BOMB_4", 5, 3069, 151, "Main Panel", "Fuselage Bombs 4 Switch")
defineToggleSwitch("NOSE_BOMBS", 5, 3071, 152, "Main Panel", "All Nose Bombs Switch")
defineToggleSwitch("TAIL_BOMBS", 5, 3073, 153, "Main Panel", "All Tail Bombs Switch")
defineRotary("FOOTAGE_SCALE", 18, 3003, 90, "Main Panel", "Footage Indicator Scale")
defineToggleSwitch("FOOTAGE_EXPOSURE", 18, 3001, 91, "Main Panel", "Footage Indicator Exposure Switch")

defineIndicatorLight("BOMB_DOOR_L", 283, "Main Panel Lights", "Bomb Door Light (yellow)")
defineIndicatorLight("MAIN_PANEL_C_LAMP_L", 271, "Main Panel Lights", "Main Panel Center Lamp (white)")
defineIndicatorLight("MAIN_PANEL_L_LAMP_L", 270, "Main Panel Lights", "Main Panel Left Lamp (white)")

--Clock
definePushButton("CLOCK_PIN_PULL", 19, 3003, 101, "Clock", "Clock Set (Pull)")  
defineRotary("CLOCK_PIN_TURN", 19, 3001, 102, "Clock", "Clock Set (Turn)")
defineRotary("CLOCK_REF_H", 19, 3005, 375, "Clock", "Clock Reference Hours")
defineRotary("CLOCK_REF_M", 19, 3007, 376, "Clock", "Clock Reference Minutes")

defineFloat("COCKPIT_HATCH", 255, {0, 1}, "Cockpit", "Cockpit Hatch")
defineFloat("REP_COMP_HDG_G", 47, {0, 1}, "Gauges", "Repeater Compass Heading")
defineFloat("REP_COMP_CRS_G", 48, {0, 1}, "Gauges", "Repeater Compass Set Course")
defineFloat("ALT_METER_100_G", 68, {0, 1}, "Gauges", "Altimeter 100")
defineFloat("ALT_METER_1000_G", 69, {0, 1}, "Gauges", "Altimeter 1000")
defineFloat("ALT_METER_10000_G", 70, {0, 1}, "Gauges", "Altimeter 10000")
defineFloat("ALT_METER_SET_PRESS_G", 71, {0, 1}, "Gauges", "Altimeter Set Pressure")
defineFloat("VARIOMETER_100_G", 67, {-1, 1}, "Gauges", "Variometer Gauge")
defineFloat("AIRSPEED_G", 64, {0.0, 0.5}, "Gauges", "Airspeed Gauge")
defineFloat("AHORIZON_BANK_G", 65, {-1, 1}, "Gauges", "AHorizon Bank")
defineFloat("AHORIZON_PITCH_G", 66, {-1, 1}, "Gauges", "AHorizon Pitch")
defineFloat("DI_G", 73, {0, 1}, "Gauges", "DI Gauge")
defineFloat("SIDESLIP_G", 75, {-1, 1}, "Gauges", "Sideslip Gauge")
defineFloat("TURN_G", 76, {-1, 1}, "Gauges", "Turn Gauge")
defineFloat("PORT_TACHO_1000_G", 50, {0, 1}, "Gauges", "Tacho 1000 Port")
defineFloat("PORT_TACHO_100_G", 51, {0, 1}, "Gauges", "Tacho 100 Port")
defineFloat("STBD_TACHO_1000_G", 52, {0, 1}, "Gauges", "Tacho 1000 Starboard")
defineFloat("STBD_TACHO_100_G", 53, {0, 1}, "Gauges", "Tacho 100 Starboard")
defineFloat("PORT_BOOST_G", 54, {0, 1}, "Gauges", "Boost Gauge Port")
defineFloat("STBD_BOOST_G", 55, {0, 1}, "Gauges", "Boost Gauge Starboard")
defineFloat("PORT_OIL_TEMP_G", 56, {-1, 1}, "Gauges", "Oil Temperature Gauge Port")
defineFloat("STBD_OIL_TEMP_G", 57, {-1, 1}, "Gauges", "Oil Temperature Gauge Starboard")
defineFloat("PORT_OIL_PRESS_G", 58, {0, 1}, "Gauges", "Oil Pressure Gauge Port")
defineFloat("STBD_OIL_PRESS_G", 59, {0, 1}, "Gauges", "Oil Pressure Gauge Starboard")
defineFloat("PORT_RAD_TEMP_G", 60, {-1, 1}, "Gauges", "Radiator Temperature Gauge Port")
defineFloat("STBD_RAD_TEMP_G", 61, {-1, 1}, "Gauges", "Radiator Temperature Gauge Starboard")
defineFloat("PORT_FUEL_IN_G", 92, {-1, 1}, "Gauges", "Inner Fuel Gauge Port")
defineFloat("STBD_FUEL_IN_G", 93, {-1, 1}, "Gauges", "Inner Fuel Gauge Starboard")
defineFloat("PORT_FUEL_OUT_G", 96, {-1, 1}, "Gauges", "Outer Fuel Gauge Port")
defineFloat("STBD_FUEL_OUT_G", 97, {-1, 1}, "Gauges", "Outer Fuel Gauge Starboard")
defineFloat("CENTR_FUEL_G", 94, {-1, 1}, "Gauges", "Fuel Gauge Central")
defineFloat("LONG_FUEL_G", 95, {-1, 1}, "Gauges", "Fuel Gauge Long Range")
defineFloat("PORT_OXY_DEV_G", 82, {0, 1}, "Gauges", "Oxygen Delivery Gauge Port")
defineFloat("PORT_OXY_SUPPLY_G", 83, {0, 1}, "Gauges", "Oxygen Supply Gauge Port")
defineFloat("STBD_OXY_DEV_G", 155, {0, 1}, "Gauges", "Oxygen Delivery Gauge Starboard")
defineFloat("STBD_OXY_SUPPLY_G", 156, {0, 1}, "Gauges", "Oxygen Supply Gauge Starboard")
defineFloat("FLAPS_G", 81, {0.0, 0.7}, "Gauges", "Flaps Gauge")
defineFloat("PNEU_PRESS_G", 85, {0, 1}, "Gauges", "Pneumatic Pressure Gauge")
defineFloat("WHEEL_BRK_L_G", 86, {0, 1}, "Gauges", "Left Wheel Brake Gauge")
defineFloat("WHEEL_BRK_R_G", 87, {0, 1}, "Gauges", "Right Wheel Brake Gauge")
defineFloat("AIR_TEMP_G", 314, {-1, 1}, "Gauges", "Air Temperature Gauge")
defineFloat("VOLTMETER_G", 103, {0, 1}, "Gauges", "Voltmeter Gauge")
defineFloat("T1154_C2_G", 207, {0.0, 0.937}, "Gauges", "T1154 C2 Gauge")
defineFloat("T1154_C4_G", 206, {0.0, 0.912}, "Gauges", "T1154 C4 Gauge")
defineFloat("T1154_C15_G", 208, {0.0, 0.937}, "Gauges", "T1154 C15 Gauge")
defineFloat("T1154_C16_G", 209, {0.0, 0.912}, "Gauges", "T1154 C16 Gauge")
defineFloat("T1154_C17_G", 205, {0.0, 0.912}, "Gauges", "T1154 C17 Gauge")
defineFloat("T1154_M1_G", 104, {0, 1}, "Gauges", "T1154 M1 Gauge")
defineFloat("T1154_M2_G", 105, {0, 1}, "Gauges", "T1154 M2 Gauge")
defineFloat("T1154_M3_G", 106, {0, 1}, "Gauges", "T1154 M3 Gauge")
defineFloat("R1155_TUNER_G", 232, {0, 1}, "Gauges", "R1155 Tuner Gauge")
defineFloat("R1155_TUNE_CAT_G", 239, {0, 1}, "Gauges", "R1155 Tuning Cathode Gauge")
defineFloat("R1155_TUNE_ANO_G", 228, {0, 1}, "Gauges", "R1155 Tuning Anode Gauge")
defineFloat("R1155_DFLH_G", 88, {-1, 1}, "Gauges", "R1155 DFLH Gauge")
defineFloat("R1155_DFRH_G", 89, {-1, 1}, "Gauges", "R1155 DFRH Gauge")

defineIndicatorLight("RADIO_A_L", 37, "Radio Lights", "Radio A Light (white)")
defineIndicatorLight("RADIO_B_L", 38, "Radio Lights", "Radio B Light (white)")
defineIndicatorLight("RADIO_C_L", 39, "Radio Lights", "Radio C Light (white)")
defineIndicatorLight("RADIO_D_L", 40, "Radio Lights", "Radio D Light (white)")
defineIndicatorLight("RADIO_TX_L", 41, "Radio Lights", "Radio TX Light (white)")

defineIndicatorLight("UV_L_L", 325, "Cockpit Lights", "Left UV Light (multi)")
defineIndicatorLight("UV_R_L", 326, "Cockpit Lights", "Right UV Light (multi)")
defineIndicatorLight("TRANS_TYPF_L", 308, "Cockpit Lights", "Transmitter TypeF Light (yellow)")
defineIndicatorLight("RED_LAMP_L_L", 379, "Cockpit Lights", "Left Red Lamp (red)")
defineIndicatorLight("WH_LAMP_R_L", 301, "Cockpit Lights", "Right White Lamp (white)")
defineIndicatorLight("WH_LAMP_F_L", 300, "Cockpit Lights", "Front White Lamp (white)")
defineIndicatorLight("WH_LAMP_L_L", 299, "Cockpit Lights", "Left White Lamp (white)")
defineIndicatorLight("DOME_LAMP_L", 276, "Cockpit Lights", "Dome Lamp (white)")
defineIndicatorLight("ANT_LAMP_L", 275, "Cockpit Lights", "Antenna Lamp (white)")


defineIndicatorLight("GAUGES_GLOW_L", 297, "Cockpit Lights", "Gauges Glow (green)")

--Externals
defineIntegerFromGetter("EXT_POSITION_LIGHT_LEFT", function()
	if LoGetAircraftDrawArgumentValue(190) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Left Position Light (red)")
defineIntegerFromGetter("EXT_POSITION_LIGHT_RIGHT", function()
	if LoGetAircraftDrawArgumentValue(191) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Right Position Light (green)")
defineIntegerFromGetter("EXT_POSITION_LIGHT_TAIL", function()
	if LoGetAircraftDrawArgumentValue(192) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Tail Position Light (white)")
defineIntegerFromGetter("EXT_POSITION_LIGHT_NOSE", function()
	if LoGetAircraftDrawArgumentValue(193) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Nose Light (white)")
defineIntegerFromGetter("EXT_POSITION_LIGHT_WINGS", function()
	if LoGetAircraftDrawArgumentValue(196) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Wing Lights (white)")
defineIntegerFromGetter("EXT_BOTTOM_LIGHT_RED", function()
	if LoGetAircraftDrawArgumentValue(200) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Red Bottom Light (red)")
defineIntegerFromGetter("EXT_BOTTOM_LIGHT_YEL", function()
	if LoGetAircraftDrawArgumentValue(201) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Yellow Bottom Light (yellow)")
defineIntegerFromGetter("EXT_BOTTOM_LIGHT_GRN", function()
	if LoGetAircraftDrawArgumentValue(201) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Green Bottom Light (green)")
defineIntegerFromGetter("EXT_LAND_LIGHT_L", function()
	if LoGetAircraftDrawArgumentValue(208) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Left Landing Light (white)")
defineIntegerFromGetter("EXT_LAND_LIGHT_R", function()
	if LoGetAircraftDrawArgumentValue(209) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Right Landing Light (white)")

defineIntegerFromGetter("EXT_WOW_NOSE", function()
	if LoGetAircraftDrawArgumentValue(1) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Weight ON Wheels Nose Gear")
defineIntegerFromGetter("EXT_WOW_RIGHT", function()
	if LoGetAircraftDrawArgumentValue(4) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Weight ON Wheels Right Gear")
defineIntegerFromGetter("EXT_WOW_LEFT", function()
	if LoGetAircraftDrawArgumentValue(6) > 0 then return 1 else return 0 end
end, 1, "External Aircraft Model", "Weight ON Wheels Left Gear")

BIOS.protocol.endModule()