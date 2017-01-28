<?php
namespace packages\whois;
class si_handler {

    function parse($data_str, $query) {
        $translate = array(
            'nic-hdl' => 'handle',
            'nameserver' => 'nserver'
        );

        $contacts = array(
            'registrant' => 'owner',
            'tech-c' => 'tech'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Ymd');
        $r['regyinfo'] = array(
            'referrer' => 'http://www.arnes.si',
            'registrar' => 'ARNES'
        );
        return $r;
    }

}
