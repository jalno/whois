<?php
namespace packages\whois;
class directnic_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact',
            'tech' => 'Technical Contact',
            'domain.name' => 'Domain Name:',
            'domain.sponsor' => 'Registration Service Provider:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.changed' => 'Record last updated ',
            'domain.created' => 'Record created on ',
            'domain.expires' => 'Record expires on ',
            '' => 'By submitting a WHOIS query'
        );

        return easy_parser($data_str, $items, 'mdy', array(), false, true);
    }

}
