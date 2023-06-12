

AZ_WAF_POLICY_NAME = {
                        "ase_listener_waf_policy"   = {
                            waf_policy_name                = "ase_listener_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }  

                        "Eliza_Allowed_IPs_in1_waf_policy"   = {
                            waf_policy_name                = "Eliza_Allowed_IPs_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "IPMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["54.209.14.208","3.226.27.167","34.195.201.40","52.203.137.88"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {
                                rule01 = {
                                rule_group_override_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                rule_group_override_disabled_rules = [  
                                    "942361",                                          
                                    "942430",
                                    "942440" 
                                ]
                                }
                            }
                        }  
                        "eP_listener_in1_waf_policy"   = {
                            waf_policy_name                = "eP_listener_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                                policy03 = {
                                custom_rule_name      = "AllowTraffic"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Allow"
                                custom_rule_priority  = 21
                                match_variable = "RequestHeaders"
                                match_variable_selector = "Ocp-Apim-Subscription-Key"

                                    
                                match_condition_operator           = "Contains"
                                match_condition_negation_condition = false
                                match_condition_match_values       = ["4fa07c49e0d84d6db18f98e16dba6540"]
                                }
                            }
                            exclusion = {
                                exclusion01 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "%"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
                                            rule_group_excluded_rules  = ["920230"]
                                            }
                                        }                                   
                                }
                                exclusion02 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "intg-encore.evicore.com"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                            rule_group_excluded_rules  = ["931130"]
                                            }
                                        }                                  
                                }  
                                exclusion03 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "\\"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941340"]
                                            }
                                        }                                   
                                }
                                exclusion04 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = ";"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941340"]
                                            }
                                        }                                   
                                }
                                exclusion05 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "\\"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942110"]
                                            }
                                        }                                   
                                }
                                exclusion06 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "A;Brand\\"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942200"]
                                            }
                                        }                                   
                                }
                                exclusion07 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "="  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430"]
                                            }
                                        }                                   
                                }	
                                exclusion08 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = ";"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430"]
                                            }
                                        }                                   
                                }       
                                exclusion09 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "not"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942130"]
                                            }
                                        }  
                                }
                                exclusion10 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "select"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942200","942260"]
                                            }
                                        }  
                                }                                                                  
                            }
                            rule_group_override = {}
                        }
                        
                        "enotification_listener_in1_waf_policy"   = {
                            waf_policy_name                = "enotification_listener_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        } 

                        "hi2br_listener_in1_waf_policy"   = {
                            waf_policy_name                = "hi2br_listener_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                                policy03 = {
                                custom_rule_name      = "Allowtraffic1"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Allow"
                                custom_rule_priority  = 12
                                match_variable = "PostArgs"
                                match_variable_selector = null

                                    
                                match_condition_operator           = "Contains"
                                match_condition_negation_condition = false
                                match_condition_match_values       = ["prefetch.serviceRequestBundle.entry.resource.meta.profile"]
                                }
                                policy04 = {
                                custom_rule_name      = "Allowtraffic4"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Allow"
                                custom_rule_priority  = 13
                                match_variable = "RequestUri"
                                match_variable_selector = null

                                    
                                match_condition_operator           = "Contains"
                                match_condition_negation_condition = false
                                match_condition_match_values       = ["/hi2br/umdtr/adaptive-questionnaire/Questionnaire/$next-question"]
                                }
                            }
                            exclusion = {
                                    exclusion01 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "iss"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                            rule_group_excluded_rules  = ["931130"]
                                            }
                                        }  
                                }
                                    exclusion02 = {
                                        exclusion_match_variable = "RequestArgNames"
                                        exclusion_match_selector = "draftOrders"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion03 = {
                                        exclusion_match_variable = "RequestArgNames"
                                        exclusion_match_selector = "fhirServer"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion04 = {
                                        exclusion_match_variable = "RequestArgNames"
                                        exclusion_match_selector = "prefetch"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion05 = {
                                        exclusion_match_variable = "RequestArgNames"
                                        exclusion_match_selector = "prefetch.serviceRequestBundle.entry.resource.identifier.system"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion06 = {
                                        exclusion_match_variable = "RequestArgValues"
                                        exclusion_match_selector = "http://bumc.org/requisitions"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion07 = {
                                        exclusion_match_variable = "RequestArgValues"
                                        exclusion_match_selector = "http://evicore.com/cpt"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion08 = {
                                        exclusion_match_variable = "RequestArgValues"
                                        exclusion_match_selector = "http://snomed.info/sct"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion09 = {
                                        exclusion_match_variable = "RequestArgValues"
                                        exclusion_match_selector = "http://terminology.hl7.org/"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion10 = {
                                        exclusion_match_variable = "RequestArgValues"
                                        exclusion_match_selector = "https://pd.mettles.com/ehrfhir"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                                rule_group_excluded_rules  = ["931130"]
                                                }
                                            }  
                                }
                                exclusion11 = {
                                        exclusion_match_variable = "RequestHeaderNames"
                                        exclusion_match_selector = "User-Agent"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-913-SCANNER-DETECTION"
                                                rule_group_excluded_rules  = ["913101"]
                                                }
                                            }  
                                }
                                exclusion12 = {
                                        exclusion_match_variable = "RequestHeaderValues"
                                        exclusion_match_selector = "python-urllib3/1.26.14"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-913-SCANNER-DETECTION"
                                                rule_group_excluded_rules  = ["913101"]
                                                }
                                            }  
                                }
                                exclusion13 = {
                                        exclusion_match_variable = "RequestArgNames"
                                        exclusion_match_selector = "context.draftOrders.entry.resource.text.div"  
                                        exclusion_selector_operator = "Contains"
                                        exclusion_rule_type = "OWASP"
                                        exclusion_rule_version = "3.2"
                                            rule_group = {
                                                rulegroup01 = {
                                                rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                                rule_group_excluded_rules  = ["941320"]
                                                }
                                            }  
                                }

                            }
                            rule_group_override = {}
                        }
                        "Provider_listener_in1_waf_policy"   = {
                            waf_policy_name                = "Provider_listener_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }
                     "UpadsPublicSvc_listener_in1_waf_policy"   = {
                            waf_policy_name                = "UpadsPublicSvc_listener_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }  
                        "Translation_listener_in1_waf_policy"   = {
                            waf_policy_name                = "Translation_listener_in1_waf_policy"
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allow_IP_List"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 10
                                match_variable = "RemoteAddr"
                                match_variable_selector = null

                                    
                                match_condition_operator           = "IPMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["64.106.168.36","4.30.179.34"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }   
                        "WebIntake_listener_in1_waf_policy"   = {
                            waf_policy_name                = "WenIntake_listener_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        } 
                        "AppealsApi_listener_in1_waf_policy"   = {
                            waf_policy_name                = "AppealsApi_listener_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }
                        "EnotifyApi_listener_in1_waf_policy"  = {
                            waf_policy_name                = "EnotifyApi_listener_in1_waf_policy"
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
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
                        "gtlmsmartsearch_in1_waf_policy"   = {
                            waf_policy_name                = "gtlmsmartsearch_in1_waf_policy" 
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 12
                                match_variable = "RemoteAddr"
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }  
                        "APIPortalEvicore_in1_waf_policy"   = {
                            waf_policy_name                = "APIPortalEvicore_in1_waf_policy"
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 12
                                match_variable = "RemoteAddr"
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }
                        "APIProxyEvicore_in1_waf_policy"   = {
                            waf_policy_name                = "APIProxyEvicore_in1_waf_policy"
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Detection"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 12
                                match_variable = "RemoteAddr"
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }
                        "fertility_listener_in1_waf_policy"   = {
                            waf_policy_name                = "fertility_listener_in1_waf_policy"
                            waf_policy_resource_group_name = "in1_rsg_apphub_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Detection"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 12
                                match_variable = "RemoteAddr"
                                match_variable_selector = null

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }
                    }