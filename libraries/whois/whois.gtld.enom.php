<?php
namespace packages\whois;
class enom_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner#0' => 'Registrant Contact',
            'owner#1' => 'REGISTRANT Contact:',
            'admin#0' => 'Administrative Contact',
            'admin#1' => 'ADMINISTRATIVE Contact:',
            'tech#0' => 'Technical Contact',
            'tech#1' => 'TECHNICAL Contact:',
            'billing#0' => 'Billing Contact',
            'billing#1' => 'BILLING Contact:',
            'domain.nserver' => 'Nameservers',
            'domain.name#0' => 'Domain name:',
            'domain.name#1' => 'Domain name-',
            'domain.sponsor' => 'Registration Service Provided By:',
            'domain.status' => 'Status:',
            'domain.created#0' => 'Creation date:',
            'domain.expires#0' => 'Expiration date:',
            'domain.created#1' => 'Created:',
            'domain.expires#1' => 'Expires:',
            'domain.created#2' => 'Start of registration-',
            'domain.expires#2' => 'Registered through-'
        );

        return easy_parser($data_str, $items, 'dmy', array(), false, true);
    }

}
