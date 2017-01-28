<?php
namespace packages\whois;
class nicline_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative contact:',
            'tech' => 'Technical contact:',
            'domain.name' => 'Domain name:',
            'domain.nserver.' => 'Domain servers in listed order:',
            'domain.created' => 'Created:',
            'domain.expires' => 'Expires:',
            'domain.changed' => 'Last updated:'
        );

        return easy_parser($data_str, $items, 'dmy');
    }

}
