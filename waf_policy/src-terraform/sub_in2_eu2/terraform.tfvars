

AZ_WAF_POLICY_NAME = {

                        "Eliza_Allowed_IPs_in2_waf_policy"   = {
                            waf_policy_name                = "Eliza_Allowed_IPs_in2_waf_policy" 
                            waf_policy_resource_group_name = "in2_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy04 = {
                                custom_rule_name      = "allow_IP_List"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 10
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "IPMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["54.209.14.208","3.226.27.167","34.195.201.40","52.203.137.88"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }
                        "UpadsPublicSvc_listener_in2_waf_policy"   = {
                            waf_policy_name                = "UpadsPublicSvc_listener_in2_waf_policy" 
                            waf_policy_resource_group_name = "in2_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 11
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }  
                        "AppealsApi_listener_in2_waf_policy"   = {
                            waf_policy_name                = "AppealsApi_listener_in2_waf_policy" 
                            waf_policy_resource_group_name = "in2_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 11
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }
                        "EnotifyApi_listener_in2_waf_policy"   = {
                            waf_policy_name                = "EnotifyApi_listener_in2_waf_policy" 
                            waf_policy_resource_group_name = "in2_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy01 = {
                                custom_rule_name      = "Allow_only_ip_list"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 10
                                match_variable = "RemoteAddr"
                                match_variable_selector = null

                                match_condition_operator           = "IPMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["170.48.0.0/16","208.242.14.0/24","8.25.203.0/24","27.251.211.238/32","64.74.126.64/26","70.39.159.0/24","72.52.96.0/26","89.167.131.0/24","104.129.192.0/23","104.129.194.0/23","104.129.196.0/23","104.129.202.0/23","136.226.0.0/16","147.161.200.0/23","147.161.204.0/23","147.161.208.0/23","147.161.252.0/23","165.225.240.0/23","165.225.242.0/23","165.225.244.0/23","165.225.246.0/23","165.225.246.0/23","165.225.44.0/24","165.225.48.0/24","165.225.6.0/23","165.225.72.0/22","165.225.75.0/24","167.18.174.0/24","167.211.174.0/24","185.46.212.0/22","199.168.148.0/24","213.152.228.0/24","216.52.207.64/26","216.218.133.192/26","2605:4300:1211::/48","2605:4300:1212::/48","2605:4300:1214::/48","2605:4300:1411::/48","2605:4300:1412::/48","2605:4300:1413::/48","2605:4300:1414::/48"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }  
                    }
