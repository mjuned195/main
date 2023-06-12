###############################################################################
#  VARIABLE DECLARATIONS MOVED TO VARIABLES.TF #
###############################################################################

###############################################################################
#  PROVIDER SETUP  #
###############################################################################

provider "azurerm" {
  features {}
}
# backend type only, remaining config specified in /environment/backend.cfg file
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.24.0"
    }
  }
  backend "azurerm" {}
}

###############################################################################
#  WAF POLICY SETUP  #
###############################################################################

resource "azurerm_web_application_firewall_policy" "RES_WAF_POLICY" {
  for_each = var.AZ_WAF_POLICY_NAME 
    name                = each.key
    resource_group_name = each.value.waf_policy_resource_group_name
    location            = each.value.waf_policy_location

    dynamic "custom_rules" {
      for_each = each.value["custom_rules"]
      content {
        name      = custom_rules.value["custom_rule_name"]
        priority  = custom_rules.value["custom_rule_priority"]
        rule_type = custom_rules.value["custom_rule_rule_type"]
        action    = custom_rules.value["custom_rule_action"]

        match_conditions {
            match_variables {
                variable_name = custom_rules.value["match_variable"]
            }
            operator           = custom_rules.value["match_condition_operator"]
            negation_condition = custom_rules.value["match_condition_negation_condition"]
            match_values       = custom_rules.value["match_condition_match_values"]
        }
      }
    }
      
    policy_settings {
      enabled                     = each.value.waf_policy_setting_enabled
      file_upload_limit_in_mb     = 100
      max_request_body_size_in_kb = 2000
      mode                        = each.value.waf_policy_mode
      request_body_check          = each.value.waf_policy_request_body_check
      }

    managed_rules {
      dynamic "exclusion" {
        for_each = each.value["exclusion"]
        content {
            match_variable            =  exclusion.value ["exclusion_match_variable"]
            selector                  =  exclusion.value ["exclusion_match_selector"]
            selector_match_operator   =  exclusion.value ["exclusion_selector_operator"]
            
            excluded_rule_set {
              rule_group {
                rule_group_name       = exclusion.value ["exclusion_rule_group_name"]
                excluded_rules        = exclusion.value ["exclusion_excluded_rules"]
              }
              type                    = exclusion.value ["exclusion_rule_type"]
              version                 = exclusion.value ["exclusion_rule_version"]
            }
        }
      }
      managed_rule_set {
        type    = "OWASP"
        version = "3.2"
        dynamic rule_group_override {
          for_each = each.value["rule_group_override"]
          content {
          rule_group_name           = rule_group_override.value["rule_group_override_rule_group_name"]
          disabled_rules            = rule_group_override.value["rule_group_override_disabled_rules"]
          }
        }         
      }
    }

    tags = {
      CostCenter = "61700200"
      AssetOwner = "eviCore Cloud COE"
      BusinessOwner = "Amie Haltom (ahaltom@evicore.com)"
      DataClassification = "Proprietary"
      AppName = "Cloud COE"
      ITSponsor = "Amie Haltom (ahaltom@evicore.com)"
      Tier = "2"
      }
    
    lifecycle {
    ignore_changes = [
      tags["createdBy"],
      tags["createdDateTime"]
      ]
    }

}