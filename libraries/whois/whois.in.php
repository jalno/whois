<?php
namespace packages\whois;
class in_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);
        $r['regyinfo'] = array(
            'referrer' => 'http://whois.registry.in',
            'registrar' => 'INRegistry'
        );
        return $r;
    }

}
