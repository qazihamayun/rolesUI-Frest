@extends('layouts.'.config('eidentity.active_layout'))
@php $app_id = config('eidentity.app_id') @endphp
<style>
    @media only screen and (max-width: 1400px) {
        html {
            zoom:75%
        }
    }
</style>
@section('content')
    <div class="row">
        <div class="col-12">
            <!-- Traffic sources -->
            <div class="card">
                <div class="card-header header-elements-inline">
                    <h6 class="card-title">{{ $title }}</h6>
                    <div class="header-elements">
                        <div class="text-right" style="text-align: right">
                            <a href="javascript:void(0)" class="btn btn-primary"
                               onclick="$('.printable_report').printThis({importCSS: true, loadCSS: '<?php echo asset('assets/css/print.css'); ?>'});">
                                <i class="fa fa-print"></i> Print
                            </a>
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-12">
                            <div class="table-responsive printable_report Landscape" style="min-height: 200px">
                                <div class="show_in_print">
                                    @include('eidentity::reports.print_header')
                                </div>
                                <table class="table table-striped" id="datatable">
                                    <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>Department</th>
                                        <th>Total Employees</th>
                                        <th>Mobile (Pending)</th>
                                        <th>Picture (Pending)</th>
                                       {{-- <th>Update Pending</th>--}}
                                        <th>Completed</th>
                                    </tr>
                                    </thead>

                                    <tbody>
                                    @foreach($departments as $item)
                                        <tr>
                                            <td>{{ $loop->iteration }}</td>
                                            <td>{{ $item->title }}</td>
                                            <td>{{ $item->employees_count }}</td>
                                            {{--<td>{{ $item->pending_update }}</td>--}}
                                            <td>{{ $item->pending_mobile }}</td>
                                            <td>{{ $item->pending_profile_pic }}</td>
                                            <td>{{ ($item->employees_count - $item->pending_update) }}</td>
                                        </tr>
                                    @endforeach
                                    </tbody>

                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- /traffic sources -->
        </div>
    </div>
@endsection

@push('stylesheets')
    <link rel="stylesheet" href="{{asset('assets/vendor/libs/datatables-bs5/datatables.bootstrap5.css')}}" />
    <link rel="stylesheet" href="{{asset('assets/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.css')}}" />
    <link rel="stylesheet" href="{{asset('assets/vendor/libs/datatables-checkboxes-jquery/datatables.checkboxes.css')}}" />
    <link rel="stylesheet" href="{{asset('assets/vendor/libs/datatables-buttons-bs5/buttons.bootstrap5.css')}}" />
    <link rel="stylesheet" href="{{asset('assets/vendor/libs/datatables-rowgroup-bs5/rowgroup.bootstrap5.css')}}" />

@endpush

@push('scripts')
    {{--    <script src="{{asset('assets/vendor/libs/i18n/i18n.js')}}"></script>--}}
    <script src="{{asset('assets/vendor/libs/datatables/jquery.dataTables.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-bs5/datatables-bootstrap5.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-responsive/datatables.responsive.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-checkboxes-jquery/datatables.checkboxes.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-buttons/datatables-buttons.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-buttons-bs5/buttons.bootstrap5.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-rowgroup/datatables.rowgroup.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-rowgroup-bs5/rowgroup.bootstrap5.js')}}"></script>
    <script src="{{asset('assets/vendor/printThis/printThis.js')}}"></script>
    <script>
        $(document).ready(function (){
            $("#datatable").DataTable({
                responsive: false,
                processing: false,
                serverSide: false,
                searching:  true,
                "order": [],
                //sorting:    false,
                scrollX:    false,
                lengthMenu: [
                    [ 50, 100, 250, 500 , -1 ],
                    [ '50', '100', '250','500' ,'All']
                ],
                "pageLength": 100,
                pagingType: "full_numbers",
                dom: 'Bfrtip',
                buttons: [
                    'copy', 'excel', 'pdf'
                ]
            });

        });
    </script>
@endpush