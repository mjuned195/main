# Azure custom WAF policies for appgw, listeners and request uri

AZ_WAF_POLICY_NAME = {

                        "IntelliPath_ut1_eu2_waf_policy"   = {
                            waf_policy_name                = "IntelliPath_ut1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "ut1_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_request_body_check  = false
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allowonlygeolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 100
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {
                                rule02 = {
                                rule_group_override_rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
                                rule_group_override_disabled_rules = [                                            
                                    "920300",
                                    "920320",
                                    "920420",
                                    "920470",
                                    "920480",
                                    "920180",
                                    "920230",
                                    "920270",
                                    "920271"
                                ]
                                }
                                rule03 = {
                                rule_group_override_rule_group_name = "REQUEST-933-APPLICATION-ATTACK-PHP"
                                rule_group_override_disabled_rules = [
                                    "933160",
                                    "933210",
                                    "933100",
                                    "933180"
                                ]                                
                                }
                                rule04 = {
                                rule_group_override_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                rule_group_override_disabled_rules = [
                                    "942110",
                                    "942130",
                                    "942370",
                                    "942430",
                                    "942440",
                                    "942200",
                                    "942260",
                                    "942300",
                                    "942150",
                                    "942210",
                                    "942350",
                                    "942400",
                                    "942410",
                                    "942120",
                                    "942180",
                                    "942190",
                                    "942310",
                                    "942330",
                                    "942340"
                                ]
                                }
                                rule05 = {
                                rule_group_override_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                rule_group_override_disabled_rules = [
                                    "941100",
                                    "941130",
                                    "941180",
                                    "941310",
                                    "941320",
                                    "941330",
                                    "941340"
                                ]
                                }
                                rule06 = {
                                rule_group_override_rule_group_name = "REQUEST-921-PROTOCOL-ATTACK"
                                rule_group_override_disabled_rules = [                                            
                                    "921120"
                                ]
                                }
                                rule07 = {
                                rule_group_override_rule_group_name = "REQUEST-930-APPLICATION-ATTACK-LFI"
                                rule_group_override_disabled_rules = [                                            
                                    "930100",
                                    "930110"
                                ]                                   
                                }
                                rule08 = {
                                rule_group_override_rule_group_name = "General"
                                rule_group_override_disabled_rules = [                                            
                                    "200002",
                                    "200003"
                                ]
                                }
                                rule09 = {
                                rule_group_override_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                rule_group_override_disabled_rules = [                                            
                                    "932110",
                                    "932130"
                                ]
                                }
                            }
                        }
                        "UpadsPublicSvc_listener_ut1_eu2_waf_policy"  = {
                            waf_policy_name                = "UpadsPublicSvc_listener_ut1_eu2_waf_policy"
                            waf_policy_resource_group_name = "ut1_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allowonlygeolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 100
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }
                    "AppealsApi_listener_ut1_eu2_waf_policy"  = {
                            waf_policy_name                = "AppealsApi_listener_ut1_eu2_waf_policy"
                            waf_policy_resource_group_name = "ut1_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allowonlygeolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 100
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }                            
                    }
