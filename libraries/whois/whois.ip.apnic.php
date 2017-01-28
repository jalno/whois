<?php
namespace packages\whois;
class apnic_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl' => 'handle',
            'person' => 'name',
            'country' => 'address',
            'netname' => 'name',
            'descr' => 'desc',
            'aut-num' => 'handle',
            'country' => 'country'
        );

        $contacts = array(
            'admin-c' => 'admin',
            'tech-c' => 'tech'
        );

        $blocks = generic_parser_a_blocks($data_str, $translate, $disclaimer);

        $r = array();

        if (isset($disclaimer) && is_array($disclaimer))
            $r['disclaimer'] = $disclaimer;

        if (empty($blocks) || !is_array($blocks['main'])) {
            $r['registered'] = 'no';
        } else {
            if (isset($blocks[$query])) {
                $as = true;
                $rb = $blocks[$query];
            } else {
                $rb = $blocks['main'];
                $as = false;
            }

            $r['registered'] = 'yes';

            while (list($key, $val) = each($contacts))
                if (isset($rb[$key])) {
                    if (is_array($rb[$key]))
                        $blk = $rb[$key][count($rb[$key]) - 1];
                    else
                        $blk = $rb[$key];

                    //$blk = strtoupper(strtok($blk,' '));
                    if (isset($blocks[$blk]))
                        $r[$val] = $blocks[$blk];
                    unset($rb[$key]);
                }

            $r['network'] = $rb;
            format_dates($r, 'Ymd');

            if (isset($r['network']['desc'])) {
                if (is_array($r['network']['desc'])) {
                    $r['owner']['organization'] = array_shift($r['network']['desc']);
                    $r['owner']['address'] = $r['network']['desc'];
                } else
                    $r['owner']['organization'] = $r['network']['desc'];

                unset($r['network']['desc']);
            }

            if (isset($r['network']['address'])) {
                if (isset($r['owner']['address']))
                    $r['owner']['address'][] = $r['network']['address'];
                else
                    $r['owner']['address'] = $r['network']['address'];

                unset($r['network']['address']);
            }
        }

        $r = array('regrinfo' => $r);
        $r['regyinfo']['type'] = 'ip';
        $r['regyinfo']['registrar'] = 'Asia Pacific Network Information Centre';
        return $r;
    }

}
