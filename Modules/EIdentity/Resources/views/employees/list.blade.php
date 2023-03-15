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
                    </div>
                    <div class="text-right" style="text-align: right">
                        <a href="{{route('eidentity.employee.create')}}" class="btn btn-primary btn-light btn-sm" >Create New Employee</a>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-12">
                            <div class="table-responsive" style="min-height: 200px">
                                <table class="table table-striped" id="datatable">
                                    <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>Name</th>
                                        <th>Father Name</th>
                                        <th>CNIC</th>
                                        <th>Designation</th>
                                        <th>BPS</th>
                                        <th>Mobile</th>
                                        <th>Picture</th>
                                        <th>Actions</th>
                                    </tr>
                                    </thead>

                                    <tbody>
                                    @foreach($employees as $item)

                                        <tr>
                                            <td>{{ $loop->iteration }}</td>
                                            <td>{{ $item->employee_name }}</td>
                                            <td>{{ $item->father_name }}</td>
                                            <td>{{ $item->cnic }}</td>
                                            <td>{{ $item->designationMF->title ?? "" }}</td>
                                            <td>{{ $item->bpsMF->title ?? "" }}</td>
                                            <td>{{ $item->mobile_no }}</td>
                                            <td>
                                                @if(!checkNullAndEmpty($item->profile_picture))
                                                    <a href="{{asset("storage/eidentity/$item->profile_picture")}}" target="_blank">
                                                        <img width="50" src="{{asset("storage/eidentity/$item->profile_picture")}}">
                                                    </a>
                                                @else
                                                    -
                                                @endif
                                            </td>
                                            <td style="width: 180px">
                                                <a href="{{ route('eidentity.employee.edit', ['id' => encrypt($item->id)]) }}" class="btn btn-warning btn-icon">
                                                    <i class="tf-icons bx bx-pencil"></i>
                                                </a>

                                            {!! Form::open(['method' => 'delete', 'route' => ['eidentity.employee.delete',encrypt($item->id)], 'class' => 'dropdown-item delete', 'style' => 'display:inline; padding: 0px']) !!}
                                            {!! Form::button('<i class="bx bx-trash tf-icons"></i>', array('class'=>'btn btn-danger btn-icon ', 'type'=>'submit')) !!}
                                            {!! Form::close() !!}
                                            </td>
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
    {{--    <link rel="stylesheet" href="{{asset('assets/vendor/libs/datatables-checkboxes-jquery/datatables.checkboxes.css')}}" />--}}
    {{--    <link rel="stylesheet" href="{{asset('assets/vendor/libs/datatables-buttons-bs5/buttons.bootstrap5.css')}}" />--}}
    {{--    <link rel="stylesheet" href="{{asset('assets/vendor/libs/datatables-rowgroup-bs5/rowgroup.bootstrap5.css')}}" />--}}

@endpush

@push('scripts')
    {{--    <script src="{{asset('assets/vendor/libs/i18n/i18n.js')}}"></script>--}}
    <script src="{{asset('assets/vendor/libs/datatables/jquery.dataTables.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-bs5/datatables-bootstrap5.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-responsive/datatables.responsive.js')}}"></script>
    <script src="{{asset('assets/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.js')}}"></script>
    {{--    <script src="{{asset('assets/vendor/libs/datatables-checkboxes-jquery/datatables.checkboxes.js')}}"></script>--}}
    {{--    <script src="{{asset('assets/vendor/libs/datatables-buttons/datatables-buttons.js')}}"></script>--}}
    {{--    <script src="{{asset('assets/vendor/libs/datatables-buttons-bs5/buttons.bootstrap5.js')}}"></script>--}}
    {{--    <script src="{{asset('assets/vendor/libs/datatables-rowgroup/datatables.rowgroup.js')}}"></script>--}}
    {{--    <script src="{{asset('assets/vendor/libs/datatables-rowgroup-bs5/rowgroup.bootstrap5.js')}}"></script>--}}

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
                pagingType: "full_numbers"
            });

        });
    </script>
@endpush

