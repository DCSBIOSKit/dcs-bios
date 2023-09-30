module("MiG-19P", package.seeall)

local Module = require("Module")

--- @class MiG_19P: Module
local MiG_19P = Module:new("MiG-19P", 0x1600, { "MiG-19P" })

--by WarLord

-- THROTTLE
MiG_19P:defineRotary("ASP_TAAGET_DIS", 11, 3314, 314, "Throttle", "ASP-5 Target Distance Selector")
MiG_19P:definePushButton("RSIU_TRANS", 17, 3315, 315, "Throttle", "RSIU-4V Transmit Button - Push to Transmit")
MiG_19P:defineToggleSwitch("AIRBRAKE_SW", 4, 3316, 316, "Throttle", "Airbrake Switch")
MiG_19P:definePushButton("AFTERBURN_DIS", 2, 3317, 317, "Throttle", "Mil-power Limit/Afterburner Disable")
MiG_19P:definePushButton("AFTERBURN_EN", 2, 3318, 318, "Throttle", "Afterburner Enable")

-- MAIN INSTRUMENTS PANEL
MiG_19P:define3PosTumb("GEAR_LEVER", 4, 3330, 330, "Landing Gear Panel", "Landing Gear Lever, Down/Neutral/Up")
MiG_19P:defineToggleSwitch("GEAR_LOCK", 4, 3331, 331, "Landing Gear Panel", "Landing Gear Lever Lock")
MiG_19P:definePushButton("GEAR_LIGHT_TEST", 10, 3333, 333, "Landing Gear Panel", "PPS-2 Landing Gear Lights Test Button - Push to test")
MiG_19P:defineToggleSwitch("EMERG_BRAKE", 4, 3301, 301, "Landing Gear Panel", "Emergency Brake")
MiG_19P:defineToggleSwitch("NOSE_GEAR_BRAKE", 4, 3302, 302, "Landing Gear Panel", "Nose Gear Brake System On/Off")

MiG_19P:defineMultipositionSwitch("NAV_LIGHTS", 5, 3261, 261, 6, 0.2, "Exterior Lights Panel", "Navigation Lights")
MiG_19P:define3PosTumb("NOSE_LIGHTS", 5, 3262, 262, "Exterior Lights Panel", "Nose Lights Switch, LANDING/OFF/TAXI")

MiG_19P:definePushButton("GIK1_ALIGN", 9, 3224, 224, "Flight Instruments Panel", "GIK-1 Needle Alignment")
MiG_19P:definePushButton("ARU2V_LAMP_TEST", 4, 3300, 300, "Flight Instruments Panel", "ARU-2V Lamp Test Button")
MiG_19P:defineRotary("GIK1_CRS_SEL", 9, 3359, 359, "Flight Instruments Panel", "GIK-1 Course Selector")
MiG_19P:definePotentiometer("AGI1_TRIM", 9, 3360, 360, { -1, 1 }, "Flight Instruments Panel", "AGI-1 Artificial Horizon Pitch Trim Knob")
MiG_19P:defineToggleSwitch("AGI1_CAGE", 9, 3361, 361, "Landing Gear Panel", "AGI-1 Artificial Horizon Cage Button - Push to cage")
MiG_19P:defineRotary("BALT_PRESS_SEL", 9, 3362, 362, "Flight Instruments Panel", "Barometric Altimeter Setting (bars)")
MiG_19P:defineToggleSwitch("INST_L_DAY_NIGHT", 6, 3363, 363, "Flight Instruments Panel", "Instruments Lamps Day/Night Mode Switch")
MiG_19P:defineRotary("CLOCK_R_KNOB_TURN", 9, 3364, 364, "Flight Instruments Panel", "AChS-1 Chronograph Right Knob (Turn)")
MiG_19P:definePushButton("CLOCK_R_KNOB_PRESS", 4, 3508, 508, "Flight Instruments Panel", "AChS-1 Chronograph Right Knob (Press)")
MiG_19P:defineRotary("CLOCK_L_KNOB_TURN", 9, 3365, 365, "Flight Instruments Panel", "AChS-1 Chronograph Left Knob (Turn)")
MiG_19P:define3PosTumb("CLOCK_L_KNOB_PRESS", 9, 3366, 366, "Flight Instruments Panel", "AChS-1 Chronograph Left Knob (PRESS)")
MiG_19P:definePushButton("GMETER_RESET", 9, 3515, 515, "Flight Instruments Panel", "AM-10 Accelerometer Min/Max G Reset Button")

-- GUNSIGHTS
MiG_19P:defineToggleSwitch("ASP5_CAGE", 11, 3355, 355, "Gunsights", "ASP-5 Sight Cage/Uncage")
MiG_19P:defineRotary("ASP5_WINGSPAN", 11, 3356, 356, "Gunsights", "ASP-5 Target Wingspan Selector")
MiG_19P:defineRotary("ASP5_BOMB_MIL", 11, 3357, 357, "Gunsights", "ASP-5 Mil Depression Setting")
MiG_19P:definePotentiometer("ASP5_BRIGHT", 11, 3358, 358, { 0, 1 }, "Gunsights", "ASP-5 Brightness")

-- RP-5 IZUMRUD
MiG_19P:defineToggleSwitch("RP5_TELEMETRY", 14, 3263, 263, "Radar", "RP-5 Radar/Telemetry Selector")

-- SPO-2 RWR
MiG_19P:defineToggleSwitch("SPO2_PW_SW", 16, 3495, 495, "Sensors", "SPO-2 SIRENA RWR Power Switch")

-- CENTER CONSOLE
MiG_19P:defineToggleSwitch("BOMB_ARM_SW", 7, 3264, 264, "Center Console", "Bombs Arm Switch")
MiG_19P:defineRotary("GUN_L_ROF", 7, 3368, 368, "Center Console", "Left Gun Ammo Counter Reset")
MiG_19P:defineRotary("GUN_R_ROF", 7, 3369, 369, "Center Console", "Right Gun Ammo Counter Reset")

-- LEFT INSTRUMENTS PANEL
MiG_19P:defineToggleSwitch("TANK1_FUEL_PUMP", 2, 3242, 242, "Bulkhead Panel 1", "Tank 1 Fuel Pump")
MiG_19P:defineToggleSwitch("TANK2_FUEL_PUMP", 2, 3243, 243, "Bulkhead Panel 1", "Tank 2 Fuel Pump")
MiG_19P:defineToggleSwitch("TANK3_FUEL_PUMP", 2, 3244, 244, "Bulkhead Panel 1", "Tank 3 Fuel Pump")
MiG_19P:defineToggleSwitch("TANK4_FUEL_PUMP", 2, 3245, 245, "Bulkhead Panel 1", "Tank 4 Fuel Pump")
MiG_19P:defineToggleSwitch("CPT_HEATING", 8, 3246, 246, "Bulkhead Panel 1", "Cockpit Heating")
MiG_19P:defineToggleSwitch("ANTI_SKID", 4, 3247, 247, "Bulkhead Panel 1", "Anti-Skid Brake")

MiG_19P:defineToggleSwitch("ENG_START", 2, 3248, 248, "Bulkhead Panel 2", "Engine Start Power Switch")
MiG_19P:defineToggleSwitch("FIRE_EX_PW_SW", 2, 3248, 249, "Bulkhead Panel 2", "Fire Extinguisher Power Switch")
MiG_19P:defineToggleSwitch("R_ENG_OIL_CUT", 2, 3250, 250, "Bulkhead Panel 2", "Right Engine Oil Cutoff")
MiG_19P:defineToggleSwitch("L_ENG_OIL_CUT", 2, 3251, 251, "Bulkhead Panel 2", "Left Engine Oil Cutoff")
MiG_19P:defineToggleSwitch("R_ENG_BURNER_CUT", 2, 3252, 252, "Bulkhead Panel 2", "Right Engine Afterburner Cut")
MiG_19P:defineToggleSwitch("L_ENG_BURNER_CUT", 2, 3253, 253, "Bulkhead Panel 2", "Left Engine Afterburner Cut")

MiG_19P:defineToggleSwitch("ARU2_MODE", 4, 3254, 254, "Bulkhead Panel 3", "ARU-2 Operational Mode (Auto/Manual)")
MiG_19P:define3PosTumb("ARU2_MANUAL", 4, 3255, 255, "Bulkhead Panel 3", "ARU-2 Manual Arm Selector")
MiG_19P:defineToggleSwitch("TP19_BRAKECUTE_COVER", 4, 3274, 274, "Bulkhead Panel 3", "TP-19 Braking Parachute Jettison Button Cover")
MiG_19P:definePushButton("TP19_BRAKECUTE_JETT", 4, 3275, 275, "Bulkhead Panel 3", "TP-19 Braking Parachute Jettison Button - Press to jettison drag chute")
MiG_19P:definePushButton("WARN_BTN", 9, 3276, 276, "Bulkhead Panel 3", "Warning Button")

MiG_19P:definePushButton("FUEL_TANK_WARN_BTN", 2, 3279, 279, "Bulkhead Panel 4", "Fuel Tanks 2,3,4 Warning Lamps Test Button")
MiG_19P:definePushButton("ENG_FIRE_TEST_BTN", 2, 3280, 280, "Bulkhead Panel 4", "Engine Fire Lamp Test Button")
MiG_19P:defineToggleSwitch("L_ENG_FUELCUT_COVER", 2, 3281, 281, "Bulkhead Panel 4", "Left Engine Fuel Cutoff Cover")
MiG_19P:defineToggleSwitch("R_ENG_FUELCUT_COVER", 2, 3282, 282, "Bulkhead Panel 4", "Right Engine Fuel Cutoff Cover")
MiG_19P:definePushButton("L_ENG_FUELCUT", 2, 3285, 285, "Bulkhead Panel 4", "Left Engine Fuel Cutoff")
MiG_19P:definePushButton("R_ENG_FUELCUT", 2, 3286, 286, "Bulkhead Panel 4", "Right Engine Fuel Cutoff")
MiG_19P:defineToggleSwitch("FIRE_EX_COVER", 2, 3283, 283, "Bulkhead Panel 4", "Fire Extinguisher Cover")
MiG_19P:definePushButton("FIRE_EX", 2, 3284, 284, "Bulkhead Panel 4", "Fire Extinguisher")

MiG_19P:defineToggleSwitch("L_ENG_START_COVER", 2, 3270, 270, "Bulkhead Panel 5", "Left Engine Start Button Cover")
MiG_19P:defineToggleSwitch("R_ENG_START_COVER", 2, 3271, 271, "Bulkhead Panel 5", "Right Engine Start Button Cover")
MiG_19P:definePushButton("L_ENG_START", 2, 3272, 272, "Bulkhead Panel 4", "Left Engine Start")
MiG_19P:definePushButton("R_ENG_START", 2, 3273, 273, "Bulkhead Panel 4", "Right Engine Start")
MiG_19P:defineToggleSwitch("L_ENG_AIR_START_COVER", 2, 3277, 277, "Bulkhead Panel 5", "Left Engine Air Start Button Cover")
MiG_19P:defineToggleSwitch("R_ENG_AIR_START_COVER", 2, 3278, 278, "Bulkhead Panel 5", "Right Engine Air Start Button Cover")
MiG_19P:definePushButton("L_ENG_AIR_START", 2, 3328, 328, "Bulkhead Panel 5", "Left Air Engine Start")
MiG_19P:definePushButton("R_ENG_AIR_START", 2, 3329, 329, "Bulkhead Panel 5", "Right Air Engine Start")

MiG_19P:defineMultipositionSwitch("ASP5_AIM_MODE", 7, 3344, 344, 4, 0.1, "Armament Sight Panel", "ASP-5 Sight Aiming Mode")
MiG_19P:defineToggleSwitch("ASP5_OP_MODE", 11, 3345, 345, "Armament Sight Panel", "ASP-5 Sight Operational Mode (Radar/Optic)")
MiG_19P:defineToggleSwitch("BOMB_REL_MODE", 7, 3346, 346, "Armament Sight Panel", "Bomb Release Mode (Single/Auto)")

MiG_19P:define3PosTumb("ROCKET_SLAVO_MODE", 7, 3336, 336, "Rocket Pod Panel", "Rockets Salvo Mode Selector")
MiG_19P:defineToggleSwitch("ROCKET_COUNTER_MODE", 7, 3337, 337, "Rocket Pod Panel", "Rockets Counter Mode (day/night)")

MiG_19P:defineToggleSwitch("RADAR_ECCM", 14, 3338, 338, "Radar Control Panel", "RP-5 Radar ECCM Mode Switch, ON/OFF")
MiG_19P:definePushButton("RADAR_BIT_TEST", 14, 3339, 339, "Radar Control Panel", "RP-5 Radar Built-In Test (BIT) Button - Press 2 seconds to start test")
MiG_19P:defineToggleSwitch("RADAR_GAUGE_MODE", 14, 3340, 340, "Radar Control Panel", "RP-5 Radar Gauge Display Mode Switch, VOLTAGE/AIR PRESSURE")
MiG_19P:defineMultipositionSwitch("RADAR_MODE", 14, 3341, 341, 4, 0.5, "Radar Control Panel", "RP-5 Radar Mode Control Switch, ON/STANDBY/OFF")
MiG_19P:defineRotary("RADAR_ANT_ELEVATION", 14, 3342, 342, "Flight Instruments Panel", "RP-5 Radar Electronic Horizon Elevation Adjustment Knob")
MiG_19P:defineToggleSwitch("RADAR_SCR_MODE", 14, 3343, 343, "Radar Control Panel", "RP-5 Radar Screen Mode Switch, DAY/NIGHT")
MiG_19P:defineToggleSwitch("RADAR_TGT_LOCK", 14, 3434, 434, "Radar Control Panel", "RP-5 Radar Target Lock Switch (AR-18-16 Tracking Antenna), ON/OFF")
MiG_19P:definePotentiometer("RADAR_SCR_BRIGHT", 14, 3486, 486, { 0, 1 }, "Radar Control Panel", "RP-5 Radar Screen Brightness Adjustment Knob")

MiG_19P:defineToggleSwitch("ARU2V_OP_MODE", 4, 3254, 254, "Flight Control", "Elevator Control (ARU-2V) Mode (Automatic/Manual)")
MiG_19P:define3PosTumb("ARU2V_MAN_SET", 4, 3255, 255, "Flight Control", "Elevator Control Manual Mode Selector (Long/Short)")
MiG_19P:defineToggleSwitch("ELEVATOR_ACT_SEL", 4, 3256, 256, "Flight Control", "Elevator Actuator Switch, HYDRAULIC(BU-14M BOOSTER)/ELECTRIC(MUS-2 SYSTEM)")
MiG_19P:define3PosTumb("AILERON_TRIM", 4, 3257, 257, "Flight Control", "Aileron Trimmer Switch, LEFT/RIGHT")
MiG_19P:defineToggleSwitch("AILERON_HYDRO", 4, 3258, 258, "Flight Control", "BU-13M Aileron Hydraulic Booster Switch, ON/OFF")
MiG_19P:defineTumb("FLAPS_LAND", 4, 3306, 306, 1, { 0, 1 }, nil, false, "Flight Control", "Flaps Landing")
MiG_19P:defineTumb("FLAPS_TAKEOFF", 4, 3307, 307, 1, { 0, 1 }, nil, false, "Flight Control", "Flaps Take Off")
MiG_19P:defineTumb("FLAPS_OFF", 4, 3308, 308, 1, { 0, 1 }, nil, false, "Flight Control", "Flaps Off")
MiG_19P:definePushButton("FLAPS_BTN_RESET", 4, 3309, 309, "Flight Control", "Flaps buttons reset")

MiG_19P:defineMultipositionSwitch("RADAR_ALT_SEL", 9, 3334, 334, 10, 0.1, "Flight Instruments", "RV-5 Radio Altimeter Minimum Altitude Selector")
MiG_19P:defineToggleSwitch("PITOT_SEL", 9, 3269, 269, "Flight Instruments", "Pitot Tube Selector, MAIN(PVD-4)/EMERGENCY(TP-156)")

MiG_19P:defineRotary("OXY_FLOW", 8, 3303, 303, "Environment", "Oxygen shut-off valve")
MiG_19P:define3PosTumb("OXY_MODE", 8, 3304, 304, "Environment", "Suit Oxygen Supply Lever, AUTOMATIC TURN-OFF/N(EUTRAL)/SUIT TURN-ON")
MiG_19P:defineToggleSwitch("OXY_CONTROL", 8, 3305, 305, "Environment", "Oxygen-Air Diluter Lever, MIXTURE/100% O2")

MiG_19P:defineToggleSwitch("ANTI_FREZZE", 8, 3291, 291, "Unknown", "Canopy Front Anti Freeze")

MiG_19P:defineToggleSwitch("FLARE_DISP", 7, 3259, 259, "Signal Flares Panel", "EKSR-46 Signal Flare Dispenser Switch, OFF/ARMED")
MiG_19P:definePushButton("FLARE_YELLOW", 7, 3287, 287, "Signal Flares Panel", "EKSR-46 Yellow Signal Flare Release Button")
MiG_19P:definePushButton("FLARE_GREEN", 7, 3288, 288, "Signal Flares Panel", "EKSR-46 Green Signal Flare Release Button")
MiG_19P:definePushButton("FLARE_RED", 7, 3289, 289, "Signal Flares Panel", "EKSR-46 Red Signal Flare Release Button")
MiG_19P:definePushButton("FLARE_WHITE", 7, 3290, 290, "Signal Flares Panel", "EKSR-46 White Signal Flare Release Button")

MiG_19P:defineTumb("BEACON_SEL", 20, 3260, 260, 1, { 0, 1 }, nil, false, "Jettison Panel", "Near/Far Beacon")
MiG_19P:defineToggleSwitch("BRAKE_PARA_BTN_COVER", 4, 3292, 292, "Jettison Panel", "TP-19 Braking Parachute Deploy Button Cover")
MiG_19P:definePushButton("BRAKE_PARA_BTN", 4, 3293, 293, "Jettison Panel", "TP-19 Braking Parachute Deploy Button - Press to deploy drag chute")
MiG_19P:defineToggleSwitch("FUEL_BOMBS_JETT_COVER", 7, 3294, 294, "Jettison Panel", "Fuel Tanks/Bombs Jettison Button Cover")
MiG_19P:definePushButton("FUEL_BOMBS_JETT", 7, 3295, 295, "Jettison Panel", "Fuel Tanks/Bombs Jettison")
MiG_19P:definePushButton("L_GUN_ARM", 7, 3296, 296, "Jettison Panel", "Left Gun Arm")
MiG_19P:definePushButton("R_GUN_ARM", 7, 3297, 297, "Jettison Panel", "Right Gun Arm")
MiG_19P:defineToggleSwitch("ROCKET_JETT_COVER", 7, 3298, 298, "Jettison Panel", "Rocket pods Jettison Button Cover")
MiG_19P:definePushButton("ROCKET_JETT", 7, 3299, 299, "Jettison Panel", "Rocket pods Jettison")

MiG_19P:defineTumb("RADIO_PRE1", 17, 3319, 319, 1, { 0, 1 }, nil, false, "Radio RSIU4V", "RSIU-4V Preset Radio Channel 1")
MiG_19P:defineTumb("RADIO_PRE2", 17, 3320, 320, 1, { 0, 1 }, nil, false, "Radio RSIU4V", "RSIU-4V Preset Radio Channel 2")
MiG_19P:defineTumb("RADIO_PRE3", 17, 3321, 321, 1, { 0, 1 }, nil, false, "Radio RSIU4V", "RSIU-4V Preset Radio Channel 3")
MiG_19P:defineTumb("RADIO_PRE4", 17, 3322, 322, 1, { 0, 1 }, nil, false, "Radio RSIU4V", "RSIU-4V Preset Radio Channel 4")
MiG_19P:defineTumb("RADIO_PRE5", 17, 3323, 323, 1, { 0, 1 }, nil, false, "Radio RSIU4V", "RSIU-4V Preset Radio Channel 5")
MiG_19P:defineTumb("RADIO_PRE6", 17, 3324, 324, 1, { 0, 1 }, nil, false, "Radio RSIU4V", "RSIU-4V Preset Radio Channel 6")
MiG_19P:defineToggleSwitch("RADIO_OPT_MODE", 17, 3325, 325, "Radio RSIU4V", "RSIU-4V Audio Output: ADF/Radio")
MiG_19P:defineToggleSwitch("RADIO_ON_OFF", 17, 3326, 326, "Radio RSIU4V", "RSIU-4V Interference Suppression Switch, ON/OFF")
MiG_19P:definePotentiometer("RADIO_VOL", 17, 3327, 327, { 0, 1 }, "Radio RSIU4V", "RSIU-4V Volume Control Knob")

-- RIGHT INSTRUMENTS PANEL
MiG_19P:defineToggleSwitch("RADIO_EMERG_PW_SW", 3, 3200, 200, "Bulkhead Panel 1", "Radios Emergency Power")
MiG_19P:defineToggleSwitch("AGI1_EMERG_PW_SW", 3, 3201, 201, "Bulkhead Panel 1", "AGI-1 Emergency Power")
MiG_19P:defineToggleSwitch("RADIO_ELECTR_PW_SW", 3, 3202, 202, "Bulkhead Panel 1", "Radios Electric Power")
MiG_19P:defineToggleSwitch("BEACON_ELECTR_PW_SW", 3, 3203, 203, "Bulkhead Panel 1", "Beacon and Radio Altimeter Electric Power")
MiG_19P:defineToggleSwitch("ELEVATOR_PW_SW", 3, 3206, 206, "Bulkhead Panel 1", "Elevator Control Electric Power")
MiG_19P:defineToggleSwitch("TRIM_PW_SW", 3, 3207, 207, "Bulkhead Panel 1", "Trim System Electric Power")
MiG_19P:defineToggleSwitch("RADIO_NAV_PW_SW", 3, 3208, 208, "Bulkhead Panel 1", "Radio Navigation Electric Power")
MiG_19P:defineToggleSwitch("PITOT_PW_SW", 3, 3209, 209, "Bulkhead Panel 1", "Pitot Heater Electric Power")
MiG_19P:defineToggleSwitch("PITOT_EMERG_PW_SW", 3, 3210, 210, "Bulkhead Panel 1", "Emergency Pitot Heater Electric Power")
MiG_19P:defineToggleSwitch("BATTERY_PW_SW", 3, 3211, 211, "Bulkhead Panel 1", "Battery Connect/Disconnect")
MiG_19P:defineToggleSwitch("L_GEN_PW_SW", 3, 3212, 212, "Bulkhead Panel 1", "Left Generator Connect/Disconnect")
MiG_19P:defineToggleSwitch("R_GEN_PW_SW", 3, 3213, 213, "Bulkhead Panel 1", "Right Generator Connect/Disconnect")
MiG_19P:defineToggleSwitch("ASP5_WARM_PW_SW", 3, 3214, 214, "Bulkhead Panel 1", "ASP-5 Sight Heater")
MiG_19P:defineToggleSwitch("ASP5_SIGHT_PW_SW", 3, 3215, 215, "Bulkhead Panel 1", "ASP-5 Sight On/Off")
MiG_19P:defineToggleSwitch("RP5_PW_SW", 3, 3216, 216, "Bulkhead Panel 1", "RP-5 Radar Electric Power")
MiG_19P:defineToggleSwitch("ORO57K_PW_SW", 3, 3217, 217, "Bulkhead Panel 1", "ORO-57K Rocket Pods Electric Power")
MiG_19P:defineToggleSwitch("L_GUN_PW_SW", 3, 3218, 218, "Bulkhead Panel 1", "Left Gun Electric Power")
MiG_19P:defineToggleSwitch("R_GUN_PW_SW", 3, 3219, 219, "Bulkhead Panel 1", "Right Gun Electric Power")
MiG_19P:defineToggleSwitch("GUN_CAM_CPT_PW_SW", 3, 3220, 220, "Bulkhead Panel 1", "Cockpit Gun Camera Power")
MiG_19P:defineToggleSwitch("GUN_CAM_NOSE_PW_SW", 3, 3221, 221, "Bulkhead Panel 1", "Nose Gun Camera Power")

MiG_19P:definePotentiometer("ARUFOSH_LAMP_L", 6, 3226, 226, { 0, 1 }, "Bulkhead Panel 2", "RUFO-45 Left Side ARUFOSH UV Lamp Intensity Control Knob")
MiG_19P:definePotentiometer("ARUFOSH_LAMP_R", 6, 3227, 227, { 0, 1 }, "Bulkhead Panel 2", "RUFO-45 Right Side ARUFOSH UV Lamp Intensity Control Knob")
MiG_19P:defineToggleSwitch("IFF_SELFDESTRUCT_COVER", 16, 3265, 265, "Bulkhead Panel 2", "SRO-2 IFF Self-destruct Button Cover")
MiG_19P:defineToggleSwitch("IFF_SELFDESTRUCT", 16, 3266, 266, "Bulkhead Panel 2", "SRO-2 IFF Self-destruct Button - Press to activate self-destruction")
MiG_19P:defineToggleSwitch("IFF_PW_COVER", 16, 3267, 267, "Bulkhead Panel 2", "SRO-2 IFF Power Switch Cover")
MiG_19P:defineToggleSwitch("IFF_PW", 16, 3268, 268, "Bulkhead Panel 2", "SRO-2 IFF Power Switch, ON/OFF")
MiG_19P:defineToggleSwitch("FLOOD_LAMP_R", 6, 3522, 522, "Bulkhead Panel 2", "Right Side Flood Lamp Switch, ON/OFF")

MiG_19P:defineMultipositionSwitch("ARK5_CHAN_SEL", 20, 3335, 335, 3, 0.5, "ARK5 Panel", "ARK-5 NEAR Frequency Band Selector Switch")
MiG_19P:defineToggleSwitch("ARK5_RECV_MODE", 20, 3347, 347, "ARK5 Panel", "ARK-5 Receiver Mode Switch, TLG(Telegraph)/TLF(Telephony)")
MiG_19P:defineMultipositionSwitch("ARK5_FREQ_SEL", 20, 3348, 348, 3, 0.5, "ARK5 Panel", "ARK-5 FAR/NDB Frequency Band Selector Switch")
MiG_19P:defineMultipositionSwitch("ARK5_MODE", 20, 3349, 349, 4, 0.1, "ARK5 Panel", "ARK-5 Function Selector Switch, OFF/COMP/ANT./LOOP")
MiG_19P:define3PosTumb("ARK5_ANT_MOV", 20, 3350, 350, "ARK5 Panel", "ARK-5 Loop Antenna Rotation Switch, L(EFT)/R(IGHT)")
MiG_19P:definePotentiometer("ARK5_INST_LIGHT", 20, 3351, 351, { 0, 1 }, "ARK5 Panel", "ARK-5 Frequency Scale Backlight Knob")
MiG_19P:definePotentiometer("ARK5_VOL", 20, 3352, 352, { 0, 1 }, "ARK5 Panel", "ARK-5 Audio Volume Knob")
MiG_19P:defineRotary("ARK5_FREQ_TUNE", 20, 3353, 353, "ARK5 Panel", "ARK-5 Frequency Fine Tuning Handle") ----

MiG_19P:defineToggleSwitch("EMERG_GEAR", 4, 3222, 222, "Right Console", "Landing Gear Emergency Deployment")
MiG_19P:defineToggleSwitch("EMERG_FLAPS", 4, 3223, 223, "Right Console", "Flaps Emergency Deployment")
MiG_19P:definePotentiometer("CPT_PRESS_LEVER", 8, 3228, 228, { 0, 1 }, "Right Console", "Cockpit Pressurization Lever")
MiG_19P:define3PosTumb("CPT_TEMP", 8, 3241, 241, "Right Console", "Cockpit Temperature Select")
MiG_19P:defineToggleSwitch("CPT_VENT_SW", 8, 3225, 225, "Right Console", "Cockpit Ventilation Switch, OPEN/CLOSE")

MiG_19P:defineToggleSwitch("CB_LOCK", 3, 3230, 230, "Circuit Breakers", "Circuit Breakers Panel Lock")
MiG_19P:defineToggleSwitch("CB_LIGHTS", 3, 3231, 231, "Circuit Breakers", "Aircraft External Lights Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_ARU2V", 3, 3232, 232, "Circuit Breakers", "ARU-2V Flight Control System Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_BOMB_FUSE", 3, 3233, 233, "Circuit Breakers", "Bomb Fuzing System Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_BOMB_RELEASE", 3, 3234, 234, "Circuit Breakers", "Bomb Release System Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_BOMB_JETT", 3, 3235, 235, "Circuit Breakers", "Bomb, Drop Tank and Rocket Emergency Jettison System Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_ARK5", 3, 3236, 236, "Circuit Breakers", "ARK-5 Radio Navigation System Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_GFAB_LIGHTS", 3, 3237, 237, "Circuit Breakers", "Landing Gear, Airbrake and Flaps Annunciator Lights Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_GFAB", 3, 3238, 238, "Circuit Breakers", "Landing Gear, Airbrake and Flaps Systems Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_AILERON_ACT", 3, 3239, 239, "Circuit Breakers", "BU-13M Aileron and BU-14M Stabilizer Hydraulic Booster Circuit Breaker")
MiG_19P:defineToggleSwitch("CB_ROCKET_PODS", 3, 3240, 240, "Circuit Breakers", "Rocket Pods Circuit Breaker")

-- CANOPY
MiG_19P:defineToggleSwitch("CANOPY_LOCK_L", 4, 3436, 429, "Canopy", "Canopy Lock Lever L")
MiG_19P:defineToggleSwitch("CANOPY_LOCK_R", 4, 3429, 429, "Canopy", "Canopy Lock Lever R")
MiG_19P:defineToggleSwitch("CANOPY_PRESS", 4, 3431, 431, "Canopy", "Canopy Pressurization Switch")
MiG_19P:defineToggleSwitch("EMERG_CANOPY", 4, 3229, 229, "Canopy", "Emergency Canopy Release Lever")
MiG_19P:defineToggleSwitch("CANOPY_OPEN", 4, 3204, 204, "Canopy", "Canopy Open/Close Handle")

-- Warning, Caution and IndicatorLights
MiG_19P:defineIndicatorLight("IFF_SELFDESTRUCT_LAMP", 205, "Warning, Caution and IndicatorLights", "SRO-2 Self-destruction Lamp (red)")
MiG_19P:defineIndicatorLight("FUEL_TANK_3_4_EMPTY", 441, "Warning, Caution and IndicatorLights", "Fuel Tanks 3 and 4 Empty Lamp (green)")
MiG_19P:defineIndicatorLight("FUEL_TANK_2_EMPTY", 442, "Warning, Caution and IndicatorLights", "Fuel Tank 2 Empty Lamp (green)")
MiG_19P:defineIndicatorLight("ENGINE_FIRE", 443, "Warning, Caution and IndicatorLights", "Engine Fire Lamp (red)")
MiG_19P:defineIndicatorLight("AILERON_TRIM_NEUTRAL_LAMP", 444, "Warning, Caution and IndicatorLights", "Aileron Trim Neutral Lamp (green)")
MiG_19P:defineIndicatorLight("GEAR_MOVE_LIGHT", 445, "Warning, Caution and IndicatorLights", "Gear in Transit Lamp (red)")
MiG_19P:defineIndicatorLight("FLAPS_DOWN", 446, "Warning, Caution and IndicatorLights", "Flaps Deployed Lamp (green)")
MiG_19P:defineIndicatorLight("AIRBRAKE_DOWN", 447, "Warning, Caution and IndicatorLights", "Airbrake Deployed Lamp (green)")
MiG_19P:defineIndicatorLight("RADAR_EMIT_LAMP", 448, "Warning, Caution and IndicatorLights", "Radar Emitting Lamp (green)")
MiG_19P:defineIndicatorLight("PITCH_TRIM_NEUTRAL_LAMP", 449, "Warning, Caution and IndicatorLights", "Pitch Trim Neutral Lamp (green)")
MiG_19P:defineIndicatorLight("BEACON_MARK_LAMP", 450, "Warning, Caution and IndicatorLights", "Beacon Marker Lamp (green)")
MiG_19P:defineIndicatorLight("ARU2V_TAKEOFF_LAND_POS_LAMP", 451, "Warning, Caution and IndicatorLights", "ARU-2V Take-off/Landing Position Lamp (green)")
MiG_19P:defineIndicatorLight("RADAR_OVERHEAT_LAMP", 452, "Warning, Caution and IndicatorLights", "Radar Overheat Lamp (TURN OFF RADAR) (red)")
MiG_19P:defineIndicatorLight("L_ENGINE_MIL", 453, "Warning, Caution and IndicatorLights", "Left Engine Mil Power Lamp (green)")
MiG_19P:defineIndicatorLight("R_ENGINE_MIL", 454, "Warning, Caution and IndicatorLights", "Right Engine Mil Power Lamp (green)")
MiG_19P:defineIndicatorLight("L_GEN_FAIL", 455, "Warning, Caution and IndicatorLights", "Left Generator Failture Lamp (red)")
MiG_19P:defineIndicatorLight("R_GEN_FAIL", 456, "Warning, Caution and IndicatorLights", "Right Generator Failture Lamp (red)")
MiG_19P:defineIndicatorLight("L_ENGINE_AB", 457, "Warning, Caution and IndicatorLights", "Left Afterburner Lamp (green)")
MiG_19P:defineIndicatorLight("R_ENGINE_AB", 458, "Warning, Caution and IndicatorLights", "Right Afterburner Lamp (green)")
MiG_19P:defineIndicatorLight("L_ENG_OIL_LOW", 459, "Warning, Caution and IndicatorLights", "Left Engine Low Oil pressure Lamp (red)")
MiG_19P:defineIndicatorLight("R_ENG_OIL_LOW", 460, "Warning, Caution and IndicatorLights", "Right Engine Low Oil pressure Lamp (red)")
MiG_19P:defineIndicatorLight("FUEL_TANK_1_EMPTY", 461, "Warning, Caution and IndicatorLights", "Fuel Tank 1 Empty Lamp (red)")
MiG_19P:defineIndicatorLight("FUEL_550_REST", 462, "Warning, Caution and IndicatorLights", "Fuel Tank 1 550 Liters Lamp (red)")
MiG_19P:defineIndicatorLight("HYD_LOW_PRESS_LAMP", 463, "Warning, Caution and IndicatorLights", "Main Hydraulic System Low Pressure Lamp (red)")
MiG_19P:defineIndicatorLight("L_ENG_AIRSTART", 464, "Warning, Caution and IndicatorLights", "Left Engine Airstart Lamp (red)")
MiG_19P:defineIndicatorLight("R_ENG_AIRSTART", 465, "Warning, Caution and IndicatorLights", "Right Engine Airstart Lamp (red)")
MiG_19P:defineIndicatorLight("BOMB_FUSE_ARM_LAMP", 466, "Warning, Caution and IndicatorLights", "Bomb Fuse Armed Lamp (red)")
MiG_19P:defineIndicatorLight("L_CANNON_ARM", 467, "Warning, Caution and IndicatorLights", "Left Cannon Armed Lamp (red)")
MiG_19P:defineIndicatorLight("R_CANNON_ARM", 468, "Warning, Caution and IndicatorLights", "Right Cannon Armed Lamp (red)")
MiG_19P:defineIndicatorLight("DROP_TANK_EMPTY", 469, "Warning, Caution and IndicatorLights", "External Drop Tank Empty Lamp (green)")
MiG_19P:defineIndicatorLight("L_WING_LOAD", 470, "Warning, Caution and IndicatorLights", "Left External Wing Load Lamp (green)")
MiG_19P:defineIndicatorLight("R_WING_LOAD", 471, "Warning, Caution and IndicatorLights", "Right External Wing Load Power Lamp (green)")
MiG_19P:defineIndicatorLight("GUNSIGHT_LOCK_LAMP", 472, "Warning, Caution and IndicatorLights", "Gunsight LOCK Lamp (green)")
MiG_19P:defineIndicatorLight("GUNSIGHT_BREAK_LAMP", 473, "Warning, Caution and IndicatorLights", "Gunsight BREAK Lamp (red)")
MiG_19P:defineIndicatorLight("RADAR_LOCK_LAMP", 474, "Warning, Caution and IndicatorLights", "Radar LOCK Lamp (green)")
MiG_19P:defineIndicatorLight("RADAR_BREAK_LAMP", 475, "Warning, Caution and IndicatorLights", "Radar BREAK Lamp (red)")
MiG_19P:defineIndicatorLight("ARK5P_PW_LAMP", 476, "Warning, Caution and IndicatorLights", "ARK-5P On/Off Lamp (green)")
MiG_19P:defineIndicatorLight("ROCKET_INST_LAMP", 477, "Warning, Caution and IndicatorLights", "Rockets Installed Lamp (green)")
MiG_19P:defineIndicatorLight("ROCKET_1_LAMP", 478, "Warning, Caution and IndicatorLights", "1 Rocket Installed Lamp (yellow)")
MiG_19P:defineIndicatorLight("ROCKET_2_LAMP", 479, "Warning, Caution and IndicatorLights", "2 Rockets Installed Lamp (yellow)")
MiG_19P:defineIndicatorLight("ROCKET_3_LAMP", 480, "Warning, Caution and IndicatorLights", "3 Rockets Installed Lamp (yellow)")
MiG_19P:defineIndicatorLight("ROCKET_4_LAMP", 481, "Warning, Caution and IndicatorLights", "4 Rockets Installed Lamp (yellow)")
MiG_19P:defineIndicatorLight("ROCKET_5_LAMP", 482, "Warning, Caution and IndicatorLights", "5 Rockets Installed Lamp (yellow)")
MiG_19P:defineIndicatorLight("ROCKET_6_LAMP", 483, "Warning, Caution and IndicatorLights", "6 Rockets Installed Lamp (yellow)")
MiG_19P:defineIndicatorLight("ROCKET_7_LAMP", 484, "Warning, Caution and IndicatorLights", "7 Rockets Installed Lamp (yellow)")
MiG_19P:defineIndicatorLight("ROCKET_8_LAMP", 485, "Warning, Caution and IndicatorLights", "8 Rockets Installed Lamp (yellow)")
MiG_19P:defineIndicatorLight("R_CONSOLE_LAMP", 487, "Warning, Caution and IndicatorLights", "Right Console Lamp (White)")
MiG_19P:defineIndicatorLight("L_CONSOLE_LAMP", 488, "Warning, Caution and IndicatorLights", "Left Console Lamp (White)")
MiG_19P:defineIndicatorLight("L_GEAR_UP", 489, "Warning, Caution and IndicatorLights", "Left Gear UP Lamp (red)")
MiG_19P:defineIndicatorLight("N_GEAR_UP", 490, "Warning, Caution and IndicatorLights", "Nose Gear UP Lamp (red)")
MiG_19P:defineIndicatorLight("R_GEAR_UP", 491, "Warning, Caution and IndicatorLights", "Right Gear UP Lamp (red)")
MiG_19P:defineIndicatorLight("L_GEAR_DOWN", 492, "Warning, Caution and IndicatorLights", "Left Gear DOWN Lamp (green)")
MiG_19P:defineIndicatorLight("N_GEAR_DOWN", 493, "Warning, Caution and IndicatorLights", "Nose Gear DOWN Lamp (green)")
MiG_19P:defineIndicatorLight("R_GEAR_DOWN", 494, "Warning, Caution and IndicatorLights", "Right Gear DOWN Lamp (green)")
MiG_19P:defineIndicatorLight("SRO2B_RWR_PW", 496, "Warning, Caution and IndicatorLights", "Radar Warning Receiver Power Lamp (red)")
MiG_19P:defineIndicatorLight("SRO2B_RWR_LOCK", 497, "Warning, Caution and IndicatorLights", "Radar Warning Receiver LOCK Lamp (red)")
MiG_19P:defineIndicatorLight("ARK5_FREQ_SCALE_L", 519, "Warning, Caution and IndicatorLights", "ARK5 Frequency Scale Light (yellow)")

-- Gauges
MiG_19P:defineFloat("ARK5_FREQ_SCALE", 354, { -1, 1 }, "Gauges", "ARK5 Frequency Scale")
MiG_19P:defineFloat("ARK5_FREQ_150_SCALE", 413, { 0, 1 }, "Gauges", "ARK5 Frequency 150-310 Scale")
MiG_19P:defineFloat("ARK5_FREQ_310_SCALE", 414, { 0, 1 }, "Gauges", "ARK5 Frequency 310-640 Scale")
MiG_19P:defineFloat("ARK5_FREQ_640_SCALE", 415, { 0, 1 }, "Gauges", "ARK5 Frequency 640-1300 Scale")
MiG_19P:defineFloat("VOLT_MANOMETER_GAUGE", 370, { 0, 0.3 }, "Gauges", "Voltmeter/Manometer Gauge")
MiG_19P:defineFloat("OXY_PRESS_GAUGE", 371, { 0, 1 }, "Gauges", "IK-18 Oxygen Pressure")
MiG_19P:defineFloat("OXY_FLOW_INDICATOR", 435, { 0, 1 }, "Gauges", "IK-18 Oxygen Flow Indicator")
MiG_19P:defineFloat("BARO_ALT_1000", 372, { 0, 1 }, "Gauges", "VD-20 Barometric Altimeter 1000m")
MiG_19P:defineFloat("BARO_ALT_100", 373, { 0, 1 }, "Gauges", "VD-20 Barometric Altimeter 100m")
MiG_19P:defineFloat("BARO_ALT_SEL", 411, { 0, 1 }, "Gauges", "VD-20 Barometric Altimeter Selected Pressure")
MiG_19P:defineFloat("GIK_HDG", 374, { 0, 1 }, "Gauges", "GIK-1 Compass Heading")
MiG_19P:defineFloat("GIK_CRS", 375, { 0, 1 }, "Gauges", "GIK-1 Compass Course")
MiG_19P:defineFloat("GIK_NDB", 376, { 0, 1 }, "Gauges", "GIK-1 Compass NDB Station")
MiG_19P:defineFloat("AIRSPEED_IAS", 377, { 0, 1 }, "Gauges", "KUS-2000 Airspeed IAS")
MiG_19P:defineFloat("AIRSPEED_TAS", 395, { 0, 1 }, "Gauges", "KUS-2000 Airspeed TAS")
MiG_19P:defineFloat("EUP53_TURN", 378, { -1, 1 }, "Gauges", "EUP-53 Turn Indicator")
MiG_19P:defineFloat("SLIP_INDICATOR", 379, { -1, 1 }, "Gauges", "Slip Indicator")
MiG_19P:defineFloat("RADAR_ALT", 380, { 0, 1 }, "Gauges", "UV-57 Radar Altimeter (raw)")
MiG_19P:defineFloat("CLOCK_FLIGHT_H", 381, { 0, 1 }, "Gauges", "Clock Flight Time Hours")
MiG_19P:defineFloat("CLOCK_FLIGHT_M", 382, { 0, 1 }, "Gauges", "Clock Flight Time Minutes")
MiG_19P:defineFloat("CLOCK_H", 383, { 0, 1 }, "Gauges", "Clock Hours")
MiG_19P:defineFloat("CLOCK_M", 384, { 0, 1 }, "Gauges", "Clock Minutes")
MiG_19P:defineFloat("CLOCK_S", 509, { 0, 1 }, "Gauges", "Clock Seconds")
MiG_19P:defineFloat("STOPWATCH_S", 510, { 0, 1 }, "Gauges", "Stopwatch Seconds")
MiG_19P:defineFloat("CLOCK_DAY", 511, { 0, 1 }, "Gauges", "Clock Daytime")
MiG_19P:defineFloat("AGI1_ART_HORIZON_PITCH", 385, { -1, 1 }, "Gauges", "AGI-1 Artificial Horizon Pitch")
MiG_19P:defineFloat("AGI1_ART_HORIZON_BANK", 385, { -1, 1 }, "Gauges", "AGI-1 Artificial Horizon Bank")
MiG_19P:defineFloat("ARU2V_STABI_IND", 388, { 0, 1 }, "Gauges", "ARU-2V Stabilizer Positin Indicator")
MiG_19P:defineFloat("EGT_GAUGE_L", 389, { 0, 1 }, "Gauges", "Dual Engine EGT Left Gauge")
MiG_19P:defineFloat("EGT_GAUGE_R", 390, { 0, 1 }, "Gauges", "Dual Engine EGT Right Gauge")
MiG_19P:defineFloat("VARIOMETER", 391, { -1, 1 }, "Gauges", "VAR-150 Variometer")
MiG_19P:defineFloat("L_RPM", 392, { 0, 1 }, "Gauges", "Left RPM Gauge")
MiG_19P:defineFloat("R_RPM", 393, { 0, 1 }, "Gauges", "Right RPM Gauge")
MiG_19P:defineFloat("MACH_IND", 394, { 0, 1 }, "Gauges", "Machmeter")
MiG_19P:defineFloat("FUEL_IND", 396, { 0, 1 }, "Gauges", "Fuel Gauge")
MiG_19P:defineFloat("FUEL_FLOW_IND", 412, { 0, 1 }, "Gauges", "Fuel Flow Meter")
MiG_19P:defineFloat("VOLTMETER", 397, { 0, 0.3 }, "Gauges", "V-1 Voltmeter")
MiG_19P:defineFloat("CPT_ALTIMETER", 398, { 0, 0.3 }, "Gauges", "Cabin Altitude")
MiG_19P:defineFloat("CPT_DIFF_PRESS", 399, { 0, 0.3 }, "Gauges", "Cabin Differential Pressure")
MiG_19P:defineFloat("OXY_SYS_ALT", 400, { 0, 1 }, "Gauges", "Oxygen System Altitude")
MiG_19P:defineFloat("BRAKE_PRESS_L", 401, { 0, 0.3 }, "Gauges", "Dual Pointer Brake Pressure Indicator Left")
MiG_19P:defineFloat("BRAKE_PRESS_R", 402, { 0, 0.3 }, "Gauges", "Dual Pointer Brake Pressure Indicator Right")
MiG_19P:defineFloat("HYD_BOOST_PRESS", 403, { 0, 1 }, "Gauges", "Booster Hydraulic System Pressure")
MiG_19P:defineFloat("G_METER", 404, { -1, 1 }, "Gauges", "G-Meter")
MiG_19P:defineFloat("G_METER_R_POINTER", 513, { 0, 1 }, "Gauges", "G-Meter Right Record Pointer")
MiG_19P:defineFloat("G_METER_L_POINTER", 514, { 0, 1 }, "Gauges", "G-Meter Left Record Pointer")
MiG_19P:defineFloat("TARGET_DIS", 405, { 0, 1 }, "Gauges", "Target Distance Gauge")
MiG_19P:defineFloat("EMERG_GEAR_PRESS_GAUGE", 406, { 0, 1 }, "Gauges", "MA-80 Pneumatic Air Pressure Emergency Landing Gear")
MiG_19P:defineFloat("HYD_SYS_GAUGE", 407, { 0, 1 }, "Gauges", "MA-250 Hydraulic System Pressure")
MiG_19P:defineFloat("EMERG_FLAPS_PRESS_GAUGE", 408, { 0, 1 }, "Gauges", "MA-250 Pneumatic Air Pressure Emergency Flaps")
MiG_19P:defineFloat("PNEU_SYS_GAUGE", 409, { 0, 1 }, "Gauges", "MA-250 Pneumatic System Air")
MiG_19P:defineFloat("ARK5P_SIG_STRENGTH", 410, { 0, 0.6 }, "Gauges", "ARK-5P Signal Strength Meter")
MiG_19P:defineFloat("ARK5P_FREQ_150", 413, { 0, 1 }, "Gauges", "ARK-5P Frequency Range 150-310")
MiG_19P:defineFloat("ARK5P_FREQ_310", 414, { 0, 1 }, "Gauges", "ARK-5P Frequency Range 310-640")
MiG_19P:defineFloat("ARK5P_FREQ_640", 415, { 0, 1 }, "Gauges", "ARK-5P Frequency Range 640-1300")
MiG_19P:defineFloat("ASP5N_TRG_SPAN", 416, { 0, 0.7 }, "Gauges", "ASP-5N Target Span Selection Scale")
MiG_19P:defineFloat("ASP5N_DIVE_ANGLE", 417, { 0, 1 }, "Gauges", "ASP-5N Dive Angle Selection Scale")
MiG_19P:defineFloat("USB1_L_AMMO_COUNT", 418, { 0, 1 }, "Gauges", "USB-1 Left Cannon Ammo Counter")
MiG_19P:defineFloat("USB1_R_AMMO_COUNT", 419, { 0, 1 }, "Gauges", "USB-1 Right Cannon Ammo Counter")

MiG_19P:defineToggleSwitch("EMERG_GEAR_HND", 4, 3505, 505, "Landing Gear Panel", "Landing Gear Emergency Handle")
MiG_19P:defineFloat("CANOPY_POS", 512, { 0, 1 }, "Gauges", "Canopy Position")

--Externals
MiG_19P:defineFloatFromDrawArgument("EXT_SPEED_BRAKE_RIGHT", 183, "External Aircraft Model", "Right Speed Brake")
MiG_19P:defineFloatFromDrawArgument("EXT_SPEED_BRAKE_LEFT", 185, "External Aircraft Model", "Left Speed Brake")

MiG_19P:defineBitFromDrawArgument("EXT_POSITION_LIGHT_LEFT", 190, "External Aircraft Model", "Left Position Light (red)")
MiG_19P:defineBitFromDrawArgument("EXT_POSITION_LIGHT_RIGHT", 192, "External Aircraft Model", "Right Position Light (green)")

MiG_19P:defineBitFromDrawArgument("EXT_WOW_NOSE", 1, "External Aircraft Model", "Weight ON Wheels Nose Gear")
MiG_19P:defineBitFromDrawArgument("EXT_WOW_RIGHT", 4, "External Aircraft Model", "Weight ON Wheels Right Gear")
MiG_19P:defineBitFromDrawArgument("EXT_WOW_LEFT", 6, "External Aircraft Model", "Weight ON Wheels Left Gear")

return MiG_19P
