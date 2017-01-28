<?php
namespace packages\whois;
class tel_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], array(), '-md--y');
        $r['regyinfo'] = array(
            'referrer' => 'http://www.telnic.org',
            'registrar' => 'Telnic'
        );
        return $r;
    }

}
