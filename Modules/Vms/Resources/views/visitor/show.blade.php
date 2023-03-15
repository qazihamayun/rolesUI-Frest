@extends('layouts.' . config('vms.active_layout'))
@php $app_id = config('vms.app_id') @endphp

@section('title', ' Show Visitor')

@section('content')
    <div class="row">
        <div class="col-12">

            <!-- Traffic sources -->
            <div class="card">
                <div class="card-header header-elements-inline">
                    <h5 class="card-title">{{ $title }}</h5>
                    <div class="header-elements">
                        <div class="form-check form-check-right form-check-switchery form-check-switchery-sm">
                        </div>
                    </div>
                </div>
                <!-- Datatable go to last page -->

                <div class="card-body">
                    <div class="row">
                        <div class="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                            <div class="widget-content widget-content-area br-6">

                                <div class="table-responsive mb-4">

                                    <table id="last-page-dt" class="table table-hover" style="width:100%">
                                        <thead>
                                            <tr>
                                                <th>Name</th>
                                                <td>
                                                    {{ $visitor->user()->exists() ? $visitor->user->name : '' }}

                                                </td>
                                            </tr>
                                            <tr>
                                                <th>Email</th>
                                                <td>
                                                    {{ $visitor->user()->exists() ? $visitor->user->email : '' }}

                                                </td>
                                            </tr>
                                            <tr>
                                                <th>Cnic</th>
                                                <td>
                                                    {{ $visitor->user()->exists() ? $visitor->user->cnic : '' }}

                                                </td>
                                            </tr>
                                            <tr>
                                                <th>Phone</th>
                                                <td>
                                                    {{ $visitor->user()->exists() ? $visitor->user->mobile : '' }}

                                                </td>
                                            </tr>
                                            <tr>
                                                <th>Department</th>
                                                <td>
                                                    {{ $visitor->department()->exists() ? $visitor->department->title : '' }}

                                                </td>
                                            </tr>
                                            <tr>
                                                <th>Purpose</th>
                                                <td>
                                                    {{ $visitor->exists() ? $visitor->purpose : '' }}

                                                </td>
                                            </tr>
                                            <tr>
                                                <th>Visiting date</th>
                                                <td>
                                                    {{ $visitor->exists() ? $visitor->visiting_date : '' }}

                                                </td>
                                            </tr>
                                        </thead>
                                    </table>
                                </div>


                            </div>
                        </div>
                    </div>
                </div>


            </div>
            <!-- /traffic sources -->

        </div>
    </div>

    <!-- Main Body Ends -->
@endsection

@push('plugin-scripts')
    {!! Html::script('assets/js/loader.js') !!}
    {!! Html::script('plugins/table/datatable/datatables.js') !!}
@endpush
