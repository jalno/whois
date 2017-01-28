<?php
namespace packages\whois;
class publicdomainregistry_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'owner#' => '(Registrant):',
            'admin' => 'Administrative Contact',
            'tech' => 'Technical Contact',
            'billing' => 'Billing Contact',
            'domain.name' => 'Domain name:',
            'domain.sponsor' => 'Registration Service Provided By:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.changed' => 'Record last updated ',
            'domain.created' => 'Record created on',
            'domain.created#' => 'Creation Date:',
            'domain.expires' => 'Record expires on',
            'domain.expires#' => 'Expiration Date:',
            'domain.status' => 'Status:'
        );

        return easy_parser($data_str, $items, 'mdy', array(), true, true);
    }

}
