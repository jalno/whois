<?php
namespace packages\whois;
class nu_handler {

    function parse($data_str, $query) {
        $items = array(
            'name' => 'Domain Name (UTF-8):',
            'created' => 'Record created on',
            'expires' => 'Record expires on',
            'changed' => 'Record last updated on',
            'status' => 'Record status:',
            'handle' => 'Record ID:'
        );

        $r = array();

        $lenght = count($data_str['rawdata']);

        $x = 0;
        foreach ($data_str['rawdata'] as $key => $val) {
            $x++;
            $val = trim($val);

            if (empty($val)) {
                continue;
            }

            if ($val == 'Domain servers in listed order:') {
                $y = 0;
                foreach ($data_str['rawdata'] as $ns) {
                    $y++;
                    $ns = trim($ns);
                    if (++$y < $x) {
                        continue;
                    }
                    $r['regrinfo']['domain']['nserver'][] = $val;
                    break;
                }
            }

            foreach ($items as $field => $match) {
                if (strstr($val, $match)) {
                    $r['regrinfo']['domain'][$field] = trim(substr($val, strlen($match)));
                    break;
                }
            }
        }

        if (isset($r['regrinfo']['domain']))
            $r['regrinfo']['registered'] = 'yes';
        else
            $r['regrinfo']['registered'] = 'no';

        $r['regyinfo'] = array(
            'whois' => 'whois.nic.nu',
            'referrer' => 'http://www.nunames.nu',
            'registrar' => '.NU Domain, Ltd'
        );

        format_dates($r, 'dmy');
        return $r;
    }

}
