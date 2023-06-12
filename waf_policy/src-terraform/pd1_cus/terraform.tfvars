
AZ_WAF_POLICY_NAME = {
                        "upx_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "upx_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2"
                            waf_policy_location            = "centralus"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy01 = {
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

                        "microstrategy_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "microstrategy_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2"
                            waf_policy_location            = "centralus"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy03 = {
                                custom_rule_name      = "allowonlygeolocation"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Block"
                                custom_rule_priority  = 90
                                match_variable = "RemoteAddr"

                                    
                                match_condition_operator           = "GeoMatch"
                                match_condition_negation_condition = true
                                match_condition_match_values       = ["US"]
                                }
                                policy04 = {
                                custom_rule_name      = "AllowTraffic"
                                custom_rule_rule_type = "MatchRule"
                                custom_rule_action    = "Allow"
                                custom_rule_priority  = 99
                                match_variable = "RequestUri"

                                    
                                match_condition_operator           = "BeginsWith"
                                match_condition_negation_condition = false
                                match_condition_match_values       = ["/MicroStrategy/asp/main.aspx?evt=3001\\u0026src=main.aspx.3001/","/MicroStrategy/asp/Main.aspx"]
                                }
                            }
                            exclusion = {
                                exclusion01 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "cptarget"  
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
                                            rule_group_excluded_rules  = ["941150"]
                                            }
                                        }  
                                }
                                exclusion02 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "dataSourcesXML"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430", "942260"]
                                            }
                                        }  
                                }
                                exclusion03 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "events"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430","942260", "942410"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
                                            rule_group_excluded_rules  = ["920271"]
                                            }
                                        }  
                                }
                                exclusion04 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "evt"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
                                            rule_group_excluded_rules  = ["920230"]
                                            }
                                            rulegroup03 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932115"]
                                            }
                                            rulegroup04 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941150"]
                                            }
                                        }  
                                }
                                exclusion05 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "filterXML"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430","942260", "942410", "942130"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941320"]
                                            }
                                        }  
                                }
                                exclusion06 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "lb"  
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
                                            rule_group_excluded_rules  = ["941150"]
                                            }
                                            rulegroup03 = {
                                            rule_group_rule_group_name = "REQUEST-932-APPLICATION-ATTACK-RCE"
                                            rule_group_excluded_rules  = ["932115"]
                                            }
                                        }  
                                }
                                exclusion07 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "loginTarget"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941150"]
                                            }
                                        }  
                                }
                                exclusion08 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "Main.aspx"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430","942450", "942120"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
                                            rule_group_excluded_rules  = ["920230"]
                                            }
                                        }  
                                }
                                exclusion09 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "params"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430","942190", "942370","942200", "942260","942330", "942340", "942300"]
                                            }
                                        }  
                                }
                                exclusion10 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "rwb"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430","942440","942450", "942210"]
                                            }

                                        }  
                                }
                                exclusion11 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "sessionStates"  
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
                                exclusion12 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "state"  
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
                                exclusion13 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "target"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-941-APPLICATION-ATTACK-XSS"
                                            rule_group_excluded_rules  = ["941150"]
                                            }
                                            rulegroup02 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942430"]
                                            }
                                        }  
                                }
                                exclusion14 = {
                                    exclusion_match_variable = "RequestArgNames"
                                    exclusion_match_selector = "Uid"  
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
                                exclusion15 = {
                                    exclusion_match_variable = "RequestCookieNames"
                                    exclusion_match_selector = "bSet"  
                                    exclusion_selector_operator = "Contains"
                                    exclusion_rule_type = "OWASP"
                                    exclusion_rule_version = "3.2"
                                        rule_group = {
                                            rulegroup01 = {
                                            rule_group_rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
                                            rule_group_excluded_rules  = ["942260", "942340", "942370", "942200"]
                                            }
                                        }  
                                }
                            }
                            rule_group_override = {}
                        }

                        "APIProxyEvicore_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "APIProxyEvicore_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2"
                            waf_policy_location            = "centralus"
                            waf_policy_mode                = "Detection"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
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
                            exclusion = {}
                            rule_group_override = {}
                        }

                        "APIPortalEvicore_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "APIPortalEvicore_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2"
                            waf_policy_location            = "centralus"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
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

                        "gtlmsmartsearch_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "gtlmsmartsearch_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2"
                            waf_policy_location            = "centralus"
                            waf_policy_mode                = "Prevention"
                            waf_policy_setting_enabled     = true
                            waf_policy_crs_version         = "3.2"
                            
                            custom_rules = {
                                policy08 = {
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
                        "eP_listener_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "eP_listener_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2" 
                            waf_policy_location            = "centralus"
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
                    "enotification_listener_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "enotification_listener_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2" 
                            waf_policy_location            = "centralus"
                            waf_policy_mode                = "Detection"
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
                    "Provider_listener_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "Provider_listener_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2"
                            waf_policy_location            = "centralus"
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
                    "PublicSvcs_listener_pd1_cus_waf_policy"   = {
                            waf_policy_name                = "PublicSvcs_listener_pd1_cus_waf_policy" 
                            waf_policy_resource_group_name = "pd1_rsg_cus_apphub_apigw_v2"
                            waf_policy_location            = "centralus"
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
                    }