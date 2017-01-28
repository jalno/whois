<?php
namespace packages\whois;
class name_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);
        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.name/',
            'registrar' => 'Global Name Registry'
        );
        return $r;
    }

}
