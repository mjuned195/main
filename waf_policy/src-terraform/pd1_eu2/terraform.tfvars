
AZ_WAF_POLICY_NAME = {

                        "Eliza_Allowed_IPs_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "Eliza_Allowed_IPs_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "doesnotcontainiplist"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 10
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "IPMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["54.208.15.211", "54.165.118.231", "54.165.234.9"]
                                }
                                policy03 = {
                                custom_rule_name      = "AllowTraffic2"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Allow"
                                custom_rule_priority  = 12
                                match_variable = "RequestBody"

                                    
                                match_condition_operator           = "Contains"
                                match_condition_negation_condition = false
                                match_condition_match_values       = ["XML"]
                                }
                            }
                            exclusion = {}
                            rule_group_override = {}
                        }  

                        "IntelliPath_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "IntelliPath_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = false
                            
                            custom_rules = {
                                policy02 = {
                                custom_rule_name      = "allow_only_geolocation"
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
                                    "942150",
                                    "942200",
                                    "942210",
                                    "942260",
                                    "942300",
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

                        "upx_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "upx_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy04 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 100
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {
                                exclusion01 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "jwtPayLoad"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942210", "942260", "942370", "942440", "942450", "942430"]
                                            }
                                        }                                   
                                    }
                                    exclusion02 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "jwtPayload"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942210", "942260", "942370", "942440", "942450", "942430"]
                                            }
                                        }                                   
                                    }
                                    exclusion03 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "AspNetCore.Antiforgery.SP9CUKGm0sw"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942210", "942440", "942450"]
                                            }
                                        }                                   
                                    }
                                    exclusion04 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "AspNetCore.Cookies"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942210", "942440", "942450"]
                                            }
                                        }                                   
                                    }
                                    exclusion05 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "SearchText"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932100", "932110"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942380","942440", "942110", "942430", ]
                                            }
                                        }                                   
                                    }
                                    exclusion06 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "contently_insights_user"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942450"]
                                            }
                                        }                                   
                                    }
                                    exclusion07 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "__RequestVerificationToken"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942450", "942440", "942370"]
                                            }
                                        }                                   
                                    }

                            }
                            rule_group_override = {}
                        }

                        "epupg_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "epupg_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy06 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 100
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {
                                    exclusion01 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "ReviewControl"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932105", "932115"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942330","942130","942440","942370","942300", "942200", "942260", "942110", "942430", "942210", "942400" ]
                                            }
                                        }                                   
                                    }
                                    exclusion02 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "__EVENTVALIDATION"
                                    exclusion_selector_operator = "Equals"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942120","942180","942340","942450","942210", "942390"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932140"]
                                            }
                                            rulegroup03 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941100", "941120", "941150"]
                                            }
                                        }                                   
                                    }
                                    exclusion03 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "__VIEWSTATE"
                                    exclusion_selector_operator = "Equals"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942120","942180","942340","942450","942210", "942390","942140", "942400", "942230", "942360"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932140", "932160"]
                                            }
                                            rulegroup03 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941100", "941120", "941130", "941150"]
                                            }
                                        }                                   
                                    }
                                    exclusion04 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "Authorization#"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942440"]
                                            }
                                        }                                   
                                    }
                                    exclusion05 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "FrOM"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942380"]
                                            }
                                        }                                   
                                    }
                                    exclusion06 = {
                                    exclusion_match_variable = "RequestArgValues"
                                    exclusion_match_selector = "northernlight.org"
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
                                    exclusion07 = {
                                    exclusion_match_variable = "RequestHeaderNames"
                                    exclusion_match_selector = "Referer"
                                    exclusion_selector_operator = "Equals"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941101"]
                                            }
                                        }                                   
                                    }
                                    exclusion08 = {
                                    exclusion_match_variable = "RequestCookieValues"
                                    exclusion_match_selector = "iptac-00A6CAE6CAEC"
                                    exclusion_selector_operator = "StartsWith"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942440"]
                                            }
                                        }                                   
                                    }
                            }
                            rule_group_override = {}
                        }

                        "epnb_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "epnb_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy07 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 100
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {
                                    exclusion01 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "access_token"
                                    exclusion_selector_operator = "Equals"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942210","942430","942440","942450"]
                                            }
                                        }                                   
                                    } 
                            }
                            rule_group_override = {}
                        }

                        "APIProxyEvicore_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "APIProxyEvicore_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Detection"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy09 = {
                                custom_rule_name      = "allow_only_geolocation"
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

                        "APIPortalEvicore_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "APIPortalEvicore_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy10 = {
                                custom_rule_name      = "allow_only_geolocation"
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
                                ]
                                }
                            }                            
                        }

                        "www_palladianhealth_com_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "www_palladianhealth_com_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy11 = {
                                custom_rule_name      = "allow_only_geolocation"
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

                        "portal_palladianhealth_com_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "portal_palladianhealth_com_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Detection"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
                            custom_rules = {
                                policy13 = {
                                custom_rule_name      = "allow_only_geolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 100
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                            }
                            exclusion = {
                                    exclusion01 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "ctl00$conContent$PatHasRedFlags"
                                    exclusion_selector_operator = "StartsWith"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932160"]
                                            }
                                        }                                   
                                    }
                                    exclusion02 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "g"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932150"]
                                            }
                                        }                                   
                                    }
                            }
                            rule_group_override = {}
                        }
                        
                        "eP_listener_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "eP_listener_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2" 
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
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
                                policy03 = {
                                custom_rule_name      = "AllowTraffic1"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Allow"
                                custom_rule_priority  = 12
                                match_variable = "RequestUri"

                                    
                                match_condition_operator           = "BeginsWith"
                                match_condition_negation_condition = false
                                match_condition_match_values       = ["/ep/continuedcareworklist/api/", "/ep/identitymanagement/api/","/pac/worklists/","/pac/calllogs/outreach"]
                                }
                            }
                            exclusion = {
                                exclusion01 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "address1"
                                    exclusion_selector_operator = "EqualsAny"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942361"]
                                            }
                                        }                                   
                                }
                                exclusion02 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "Address1"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942361", "942440"]
                                            }
                                        }                                  
                                }
                                exclusion03 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "backgroundInformation.medicalHistory.metaData.priorMedicalHistory.checkedDescription"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942320"]
                                            }
                                        }                                  
                                }  
                                exclusion04 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "backgroundInformation.socialSupport.metaData.HESS_REASON"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942210"]
                                            }
                                        }                                   
                                }  
                                exclusion05 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "cookie"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941340"]
                                            }
                                        }                                    
                                }
                                exclusion06 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "firstName"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932150"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942110"]
                                            }
                                        }                                    
                                }                                
                                exclusion07 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "id"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932150"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942110","942260","942370","942430","942450", "942440", "942400"]
                                            }
                                            rulegroup03 = {
                                            rule_group_rule_group_name = "REQUEST-931-APPLICATION-ATTACK-RFI"
                                            rule_group_excluded_rules  = ["931130"]
                                            }
                                        }                                    
                                }   
                                exclusion08 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "joinCode"
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
                                exclusion09 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "lastName"
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
                                exclusion10 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "medicalSurvey.skilledMedicalNeeds.metaData.MedicalNeeds"
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
                                exclusion11 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "message"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941320"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942130"]                                        
                                            }
                                        }
                                } 
                                exclusion12 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "Name"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932115"]
                                            }
                                        }                                        
                                }
                                exclusion13 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "notes"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942210", "942400", "942440"]
                                            }
                                        }                                        
                                }
                                exclusion14 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "outcomes"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942440"]
                                            }
                                        }                                        
                                }   
                                exclusion15 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "referer"
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
                                exclusion16 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "request.diagnoses.primaryCode.diagnosisDescription"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-933-APPLICATION-ATTACK-PHP"
                                            rule_group_excluded_rules  = ["933210"]
                                            }
                                        }                                        
                                } 
                                exclusion17 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "requestForCareCoordination.procedureCodes.name"
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
                                 exclusion18 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "requestForCareCoordination.reasonDetails.notes"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942440"]
                                            }
                                        }                                        
                                } 
                                exclusion19 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "RequestForService.diagnoses.primaryCode.diagnosisDescription"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-933-APPLICATION-ATTACK-PHP"
                                            rule_group_excluded_rules  = ["933210"]
                                            }
                                        }                                        
                                } 
                                exclusion20 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "RequestForService.providers.address1"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942361"]
                                            }
                                        }                                        
                                } 
                                exclusion21 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "riskAssessmentDTO.questionGroups.questions.questionText"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942200","942260","942340","942370","942430"]
                                            }
                                        }                                        
                                }                                                                
                                exclusion22 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "riskAssessmentDTO.questionGroups.questions.score"
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
                                exclusion23 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "searchArguments"
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
                                exclusion24 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "searchinput"
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
                                exclusion25 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "SearchInput"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942440","942130","942210","942260","942370","942400","942430"]
                                            }
                                        }                                        
                                }
                                exclusion26 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "sec-ch-ua"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942330","942430"]
                                            }
                                        }                                        
                                }
                                exclusion27 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "sec-ch-ua-platform"
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
                                exclusion28 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "uploadDetails"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942260","942340","942370","942430","942200"]
                                            }
                                        }                                        
                                }
                                exclusion29 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "x-arr-ssl"
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
                                exclusion30 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "requestForCareCoordination.procedureCodes.name"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942120"]
                                            }
                                        }                                        
                                }
                                exclusion31 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "term"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942410", "942150"]
                                            }
                                        }                                        
                                }
                                exclusion31 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "RequestForService.submittedProcedureCodes.name"
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
                                exclusion32 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "RequestForService.diagnoses.additionalCodes.diagnosisDescription"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-933-APPLICATION-ATTACK-PHP"
                                            rule_group_excluded_rules  = ["933210"]
                                            }
                                        }                                        
                                }
                                exclusion33 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "medicalSurvey.skilledMedicalNeeds.metaData.AdditionalNote"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942100"]
                                            }
                                        }                                        
                                }
                                 exclusion34 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "medicalSurvey.physicalTherapy.metaData.AmbulationDist"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942110","942330"]
                                            }
                                        }                                        
                                }

                            }
                            rule_group_override = {}
                        } 
                    "Provider_listener_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "Provider_listener_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
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
                            exclusion = {
                                    exclusion01 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "lastName"
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
                                    exclusion02 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "MemberNetworkCode"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942100"]
                                            }
                                        } 
                                    }                                       
                                    exclusion03 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "notes"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942130","942330","942110"]
                                            }
                                        }                                        
                                    }
                                    exclusion04 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "SearchInput"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932115", "932105"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942110","942210", "942260", "942370", "942430", "942440"]
                                            }
                                        }                                        
                                    }
                                    exclusion05 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "SearchInput"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942440"]
                                            }
                                        }
                                    }           
                                    exclusion06 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "contently_insights_user"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942450"]
                                            }
                                        }                                   
                                    }
                            }
                            rule_group_override = {
                                    rule01 = {
                                    rule_group_override_rule_group_name     = "REQUEST-920-PROTOCOL-ENFORCEMENT"
                                    rule_group_override_disabled_rules      = [
                                        "920230",
                                    ]
                                }
                            }
                        }
                        "Translation_listener_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "Translation_listener_pd1_eu2_waf_policy"
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
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
                    "PublicSvcs_listener_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "PublicSvcs_listener_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
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
                        "WebIntakeProcedureCodes_listener_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "WebIntakeProcedureCodes_listener_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
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
                            exclusion = {
                                    exclusion01 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "contently_insights_user"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942450"]
                                            }
                                        }                                   
                                    }
                                    exclusion02 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "ab.storage.deviceId.c7739970-c490-4772-aa67-2b5c1403137e"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942260", "942200", "942370"]
                                            }
                                        }                                   
                                    }
                                    exclusion03 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "iptac-CC46D6F87CE6-FCH1949V197"
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942440"]
                                            }
                                        }                                   
                                    }
                                
                            }
                            rule_group_override = {}
                        }
                        "AppealsApi_listener_pd1_waf_policy"   = {
                            waf_policy_name                = "AppealsApi_listener_pd1_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
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
                        "fertility_listener_pd1_eu2_waf_policy"   = {
                            waf_policy_name                = "fertility_listener_pd1_eu2_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_apphub_eu2_apigw_v2"
                            waf_policy_location            = "eastus2"
                            waf_policy_mode                = "Detection"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            waf_policy_request_body_check  = true
                            
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
                    }

