<?php
namespace packages\whois;
class fabulous_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Domain ' . $query . ':',
            'admin' => 'Administrative contact:',
            'tech' => 'Technical contact:',
            'billing' => 'Billing contact:',
            '' => 'Record dates:'
        );

        $r = easy_parser($data_str, $items, 'mdy', array(), false, true);

        if (!isset($r['tech']))
            $r['tech'] = $r['billing'];

        if (!isset($r['admin']))
            $r['admin'] = $r['tech'];

        return $r;
    }

}
